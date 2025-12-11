package inventory

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/anchore/ecs-inventory/internal/logger"
	"github.com/anchore/ecs-inventory/internal/tracker"
	"github.com/anchore/ecs-inventory/pkg/reporter"
)

const unknown = "UNKNOWN"

// Check if AWS credentials are present in the loaded config
func checkAWSCredentials(ctx context.Context, cfg aws.Config) error {
	_, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		fmt.Println(
			"Unable to get AWS credentials, please check ~/.aws/credentials file or environment variables are set correctly.",
		)
		return fmt.Errorf("unable to get AWS credentials: %w", err)
	}
	return nil
}

func fetchClusters(ctx context.Context, client ECSAPI) ([]string, error) {
	defer tracker.TrackFunctionTime(time.Now(), "Fetching list of clusters")
	input := &ecs.ListClustersInput{}

	result, err := client.ListClusters(ctx, input)
	if err != nil {
		return nil, err
	}

	return result.ClusterArns, nil
}

func fetchTasksFromCluster(ctx context.Context, client ECSAPI, cluster string) ([]string, error) {
	defer tracker.TrackFunctionTime(time.Now(), fmt.Sprintf("Fetching tasks from cluster: %s", cluster))
	input := &ecs.ListTasksInput{
		Cluster: aws.String(cluster),
	}

	result, err := client.ListTasks(ctx, input)
	if err != nil {
		return nil, err
	}

	return result.TaskArns, nil
}

func fetchServicesFromCluster(ctx context.Context, client ECSAPI, cluster string) ([]string, error) {
	defer tracker.TrackFunctionTime(time.Now(), fmt.Sprintf("Fetching services from cluster: %s", cluster))
	input := &ecs.ListServicesInput{
		Cluster: aws.String(cluster),
	}

	result, err := client.ListServices(ctx, input)
	if err != nil {
		return nil, err
	}

	return result.ServiceArns, nil
}

func fetchContainersFromTasks(ctx context.Context, client ECSAPI, cluster string, tasks []string) ([]reporter.Container, error) {
	defer tracker.TrackFunctionTime(time.Now(), fmt.Sprintf("Fetching Containers from tasks for cluster: %s", cluster))
	input := &ecs.DescribeTasksInput{
		Cluster: aws.String(cluster),
		Tasks:   tasks,
	}

	results, err := client.DescribeTasks(ctx, input)
	if err != nil {
		return nil, err
	}
	containerTagMap := buildContainerTagMap(results.Tasks)
	containers := []reporter.Container{}
	for _, task := range results.Tasks {
		for _, container := range task.Containers {
			digest := ""
			if container.ImageDigest != nil {
				digest = *container.ImageDigest
			} else {
				if container.ContainerArn != nil {
					logger.Log.Warnf("No image digest found for container: %s", *container.ContainerArn)
				} else {
					logger.Log.Warn("No image digest found for container (nil ARN)")
				}
				logger.Log.Warn("Ensure all ECS container hosts are running at least ECS Agent 1.70.0, which fixed a bug where image digests were not returned in the DescribeTasks API response.")
			}
			containerImage := getContainerImageTag(containerTagMap, &container)
			taskARN := ""
			if task.TaskArn != nil {
				taskARN = *task.TaskArn
			}
			containerARN := ""
			if container.ContainerArn != nil {
				containerARN = *container.ContainerArn
			}

			containers = append(containers, reporter.Container{
				ARN:         containerARN,
				ImageTag:    containerImage,
				ImageDigest: digest,
				TaskARN:     taskARN,
			})
		}
	}

	return containers, nil
}

func getContainerImageTag(containerTagMap map[string]string, container *ecstypes.Container) string {
	// Fix container image tag if it contains an @ symbol
	if container.Image != nil && strings.Contains(*container.Image, "@") {
		// replace the image tag with the correct one
		if container.ImageDigest != nil {
			if tag, ok := containerTagMap[*container.ImageDigest]; ok {
				return tag
			}
		}
		if container.Image != nil {
			logger.Log.Warnf("No image tag found for container setting to UNKNOWN: %s", *container.Image)
			parts := strings.Split(*container.Image, "@")
			return parts[0] + ":UNKNOWN"
		}
		return unknown
	}
	if container.Image != nil {
		return *container.Image
	}
	return unknown
}

// Build a map of container image digests to image tags
func buildContainerTagMap(tasks []ecstypes.Task) map[string]string {
	containerMap := make(map[string]string)
	for _, task := range tasks {
		for _, container := range task.Containers {
			// check if the container tag consists of an @ symbol
			if container.Image != nil && !strings.Contains(*container.Image, "@") {
				// Good tag image, store map
				if container.ImageDigest != nil {
					containerMap[*container.ImageDigest] = *container.Image
				}
			}
		}
	}
	return containerMap
}

// Using the clusterARN and service name, construct the service ARN.
// The DescribeTasks API does not return the service ARN only the service name.
func constructServiceARN(clusterARN string, serviceName string) (string, error) {
	arnParts := strings.Split(clusterARN, ":")
	if len(arnParts) != 6 {
		return "", fmt.Errorf("unable to parse cluster ARN: %s", clusterARN)
	}
	region := arnParts[3]
	accountID := arnParts[4]

	clusterParts := strings.Split(arnParts[5], "/")
	if len(clusterParts) < 2 {
		return "", fmt.Errorf("unable to parse cluster ARN: %s", clusterARN)
	}
	clusterName := clusterParts[1]

	if region == "" || clusterName == "" || accountID == "" {
		return "", fmt.Errorf("unable to parse cluster ARN: %s", clusterARN)
	}

	return fmt.Sprintf("arn:aws:ecs:%s:%s:service/%s/%s", region, accountID, clusterName, serviceName), nil
}

func fetchTasksMetadata(ctx context.Context, client ECSAPI, cluster string, tasks []string) ([]reporter.Task, error) {
	input := &ecs.DescribeTasksInput{
		Cluster: aws.String(cluster),
		Tasks:   tasks,
	}

	results, err := client.DescribeTasks(ctx, input)
	if err != nil {
		return nil, err
	}

	var tasksMetadata []reporter.Task
	for _, task := range results.Tasks {
		// Tags may not be present in the task response so we need to fetch them explicitly
		taskARN := ""
		if task.TaskArn != nil {
			taskARN = *task.TaskArn
		}
		tagMap, err := fetchTagsForResource(ctx, client, taskARN)
		if err != nil {
			return nil, err
		}

		tMetadata := reporter.Task{
			ARN:        taskARN,
			TaskDefARN: "",
			Tags:       tagMap,
		}
		if task.TaskDefinitionArn != nil {
			tMetadata.TaskDefARN = *task.TaskDefinitionArn
		}

		// Group may be nil
		if task.Group != nil {
			groupParts := strings.Split(*task.Group, ":")
			if len(groupParts) != 2 {
				return nil, fmt.Errorf("unable to parse task group: %s", *task.Group)
			}
			groupType := groupParts[0]
			if groupType == "service" {
				serviceName := groupParts[1]
				serviceArn, err := constructServiceARN(*task.ClusterArn, serviceName)
				if err != nil {
					return nil, err
				}
				tMetadata.ServiceARN = serviceArn
			}
		}

		tasksMetadata = append(tasksMetadata, tMetadata)
	}

	return tasksMetadata, nil
}

func fetchServicesMetadata(ctx context.Context, client ECSAPI, cluster string, services []string) ([]reporter.Service, error) {
	input := &ecs.DescribeServicesInput{
		Cluster:  aws.String(cluster),
		Services: services,
	}

	results, err := client.DescribeServices(ctx, input)
	if err != nil {
		return nil, err
	}

	var servicesMetadata []reporter.Service
	for _, service := range results.Services {
		// Tags may not be present in the service response so we need to fetch them explicitly
		serviceARN := ""
		if service.ServiceArn != nil {
			serviceARN = *service.ServiceArn
		}
		tagMap, err := fetchTagsForResource(ctx, client, serviceARN)
		if err != nil {
			return nil, err
		}

		servicesMetadata = append(servicesMetadata, reporter.Service{
			ARN:  serviceARN,
			Tags: tagMap,
		})
	}

	return servicesMetadata, nil
}

func fetchTagsForResource(ctx context.Context, client ECSAPI, resourceARN string) (map[string]string, error) {
	// If resourceARN is empty or malformed, return empty map
	if resourceARN == "" {
		return map[string]string{}, nil
	}

	input := &ecs.ListTagsForResourceInput{
		ResourceArn: aws.String(resourceARN),
	}

	result, err := client.ListTagsForResource(ctx, input)
	if err != nil {
		return nil, err
	}

	tags := make(map[string]string)
	for _, tag := range result.Tags {
		if tag.Key != nil && tag.Value != nil {
			tags[*tag.Key] = *tag.Value
		}
	}

	return tags, nil
}
