package inventory

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/ecs/ecsiface"

	"github.com/anchore/ecs-inventory/internal/logger"
	"github.com/anchore/ecs-inventory/internal/tracker"
	"github.com/anchore/ecs-inventory/pkg/reporter"
)

// Check if AWS are present, should be stored in ~/.aws/credentials
func checkAWSCredentials(sess *session.Session) error {
	_, err := sess.Config.Credentials.Get()
	if err != nil {
		fmt.Println(
			"Unable to get AWS credentials, please check ~/.aws/credentials file or environment variables are set correctly.",
		)
		return fmt.Errorf("unable to get AWS credentials: %w", err)
	}
	return nil
}

func fetchClusters(client ecsiface.ECSAPI) ([]*string, error) {
	defer tracker.TrackFunctionTime(time.Now(), "Fetching list of clusters")
	input := &ecs.ListClustersInput{}

	result, err := client.ListClusters(input)
	if err != nil {
		return nil, err
	}

	return result.ClusterArns, nil
}

func fetchTasksFromCluster(client ecsiface.ECSAPI, cluster string) ([]*string, error) {
	defer tracker.TrackFunctionTime(time.Now(), fmt.Sprintf("Fetching tasks from cluster: %s", cluster))
	input := &ecs.ListTasksInput{
		Cluster: aws.String(cluster),
	}

	result, err := client.ListTasks(input)
	if err != nil {
		return nil, err
	}

	return result.TaskArns, nil
}

func fetchServicesFromCluster(client ecsiface.ECSAPI, cluster string) ([]*string, error) {
	defer tracker.TrackFunctionTime(time.Now(), fmt.Sprintf("Fetching services from cluster: %s", cluster))
	input := &ecs.ListServicesInput{
		Cluster: aws.String(cluster),
	}

	result, err := client.ListServices(input)
	if err != nil {
		return nil, err
	}

	return result.ServiceArns, nil
}

func fetchContainersFromTasks(client ecsiface.ECSAPI, cluster string, tasks []*string) ([]reporter.Container, error) {
	defer tracker.TrackFunctionTime(time.Now(), fmt.Sprintf("Fetching Containers from tasks for cluster: %s", cluster))
	input := &ecs.DescribeTasksInput{
		Cluster: aws.String(cluster),
		Tasks:   tasks,
	}

	results, err := client.DescribeTasks(input)
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
			// Fix container image tag if it contains an @ symbol
			if strings.Contains(*container.Image, "@") {
				if tag, ok := containerTagMap[digest]; ok {
					// replace the image tag with the correct one
					container.Image = &tag
				}
			}
			containers = append(containers, reporter.Container{
				ARN:         *container.ContainerArn,
				ImageTag:    *container.Image,
				ImageDigest: digest,
				TaskARN:     *task.TaskArn,
			})
		}
	}

	return containers, nil
}

// Build a map of container image digests to image tags
func buildContainerTagMap(tasks []*ecs.Task) map[string]string {
	containerMap := make(map[string]string)
	for _, task := range tasks {
		for _, container := range task.Containers {
			// check if the container tag consists of an @ symbol
			if !strings.Contains(*container.Image, "@") {
				// Good tag image, store map
				containerMap[*container.ImageDigest] = *container.Image
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

func fetchTasksMetadata(client ecsiface.ECSAPI, cluster string, tasks []*string) ([]reporter.Task, error) {
	input := &ecs.DescribeTasksInput{
		Cluster: aws.String(cluster),
		Tasks:   tasks,
	}

	results, err := client.DescribeTasks(input)
	if err != nil {
		return nil, err
	}

	var tasksMetadata []reporter.Task
	for _, task := range results.Tasks {
		// Tags may not be present in the task response so we need to fetch them explicitly
		tagMap, err := fetchTagsForResource(client, *task.TaskArn)
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

func fetchServicesMetadata(client ecsiface.ECSAPI, cluster string, services []*string) ([]reporter.Service, error) {
	input := &ecs.DescribeServicesInput{
		Cluster:  aws.String(cluster),
		Services: services,
	}

	results, err := client.DescribeServices(input)
	if err != nil {
		return nil, err
	}

	var servicesMetadata []reporter.Service
	for _, service := range results.Services {
		// Tags may not be present in the service response so we need to fetch them explicitly
		tagMap, err := fetchTagsForResource(client, *service.ServiceArn)
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

func fetchTagsForResource(client ecsiface.ECSAPI, resourceARN string) (map[string]string, error) {
	input := &ecs.ListTagsForResourceInput{
		ResourceArn: aws.String(resourceARN),
	}

	result, err := client.ListTagsForResource(input)
	if err != nil {
		return nil, err
	}

	tags := make(map[string]string)
	for _, tag := range result.Tags {
		tags[*tag.Key] = *tag.Value
	}

	return tags, nil
}
