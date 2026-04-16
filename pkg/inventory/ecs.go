package inventory

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/anchore/ecs-inventory/internal/logger"
	"github.com/anchore/ecs-inventory/internal/tracker"
	"github.com/anchore/ecs-inventory/pkg/reporter"
)

// ECSClient defines the subset of the ECS API used by this package.
type ECSClient interface {
	ListClusters(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	ListTasks(ctx context.Context, params *ecs.ListTasksInput, optFns ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	ListServices(ctx context.Context, params *ecs.ListServicesInput, optFns ...func(*ecs.Options)) (*ecs.ListServicesOutput, error)
	DescribeTasks(ctx context.Context, params *ecs.DescribeTasksInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
	DescribeServices(ctx context.Context, params *ecs.DescribeServicesInput, optFns ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error)
	ListTagsForResource(ctx context.Context, params *ecs.ListTagsForResourceInput, optFns ...func(*ecs.Options)) (*ecs.ListTagsForResourceOutput, error)
}

// Check if AWS credentials are present
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

func fetchClusters(ctx context.Context, client ECSClient) ([]string, error) {
	defer tracker.TrackFunctionTime(time.Now(), "Fetching list of clusters")
	input := &ecs.ListClustersInput{}

	result, err := client.ListClusters(ctx, input)
	if err != nil {
		return nil, err
	}

	return result.ClusterArns, nil
}

func fetchTasksFromCluster(ctx context.Context, client ECSClient, cluster string) ([]string, error) {
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

func fetchServicesFromCluster(ctx context.Context, client ECSClient, cluster string) ([]string, error) {
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

func fetchContainersFromTasks(ctx context.Context, client ECSClient, cluster string, tasks []string) ([]reporter.Container, error) {
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
				logger.Log.Warnf("No image digest found for container: %s", *container.ContainerArn)
				logger.Log.Warn("Ensure all ECS container hosts are running at least ECS Agent 1.70.0, which fixed a bug where image digests were not returned in the DescribeTasks API response.")
			}
			containerImage := getContainerImageTag(containerTagMap, container)
			containers = append(containers, reporter.Container{
				ARN:         *container.ContainerArn,
				ImageTag:    containerImage,
				ImageDigest: digest,
				TaskARN:     *task.TaskArn,
			})
		}
	}

	return containers, nil
}

func getContainerImageTag(containerTagMap map[string]string, container types.Container) string {
	// Fix container image tag if it contains an @ symbol
	if strings.Contains(*container.Image, "@") {
		// replace the image tag with the correct one
		if tag, ok := containerTagMap[*container.ImageDigest]; ok {
			return tag
		}
		logger.Log.Warnf("No image tag found for container setting to UNKNOWN: %s", *container.Image)
		return strings.Split(*container.Image, "@")[0] + ":UNKNOWN"
	}
	return *container.Image
}

// Build a map of container image digests to image tags
func buildContainerTagMap(tasks []types.Task) map[string]string {
	containerMap := make(map[string]string)
	for _, task := range tasks {
		for _, container := range task.Containers {
			// check if the container tag consists of an @ symbol
			if !strings.Contains(*container.Image, "@") {
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

func fetchTasksMetadata(ctx context.Context, client ECSClient, cluster string, tasks []string) ([]reporter.Task, error) {
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
		tagMap, err := fetchTagsForResource(ctx, client, *task.TaskArn)
		if err != nil {
			return nil, err
		}

		tMetadata := reporter.Task{
			ARN:        *task.TaskArn,
			TaskDefARN: *task.TaskDefinitionArn,
			Tags:       tagMap,
		}

		// Group will be "servive:serviceName" if the task is part of a service, otherwise it will be
		// "family:taskDefinitionFamily" if the task is not part of a service.
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

		tasksMetadata = append(tasksMetadata, tMetadata)
	}

	return tasksMetadata, nil
}

func fetchServicesMetadata(ctx context.Context, client ECSClient, cluster string, services []string) ([]reporter.Service, error) {
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
		tagMap, err := fetchTagsForResource(ctx, client, *service.ServiceArn)
		if err != nil {
			return nil, err
		}

		servicesMetadata = append(servicesMetadata, reporter.Service{
			ARN:  *service.ServiceArn,
			Tags: tagMap,
		})
	}

	return servicesMetadata, nil
}

func fetchTagsForResource(ctx context.Context, client ECSClient, resourceARN string) (map[string]string, error) {
	input := &ecs.ListTagsForResourceInput{
		ResourceArn: aws.String(resourceARN),
	}

	result, err := client.ListTagsForResource(ctx, input)
	if err != nil {
		return nil, err
	}

	tags := make(map[string]string)
	for _, tag := range result.Tags {
		tags[*tag.Key] = *tag.Value
	}

	return tags, nil
}
