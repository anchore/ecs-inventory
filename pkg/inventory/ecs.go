package inventory

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/ecs/ecsiface"

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
	input := &ecs.ListClustersInput{}

	result, err := client.ListClusters(input)
	if err != nil {
		return nil, err
	}

	return result.ClusterArns, nil
}

func fetchTasksFromCluster(client ecsiface.ECSAPI, cluster string) ([]*string, error) {
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
	input := &ecs.DescribeTasksInput{
		Cluster: aws.String(cluster),
		Tasks:   tasks,
	}

	results, err := client.DescribeTasks(input)
	if err != nil {
		return nil, err
	}

	containers := []reporter.Container{}

	for _, task := range results.Tasks {
		for _, container := range task.Containers {
			digest := ""
			if container.ImageDigest != nil {
				digest = *container.ImageDigest
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

		tasksMetadata = append(tasksMetadata, reporter.Task{
			ARN:        *task.TaskArn,
			ClusterARN: *task.ClusterArn,
			TaskDefARN: *task.TaskDefinitionArn,
			Tags:       tagMap,
			// ServiceARN: *task.ServiceArn,
		})
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
			ARN:        *service.ServiceArn,
			ClusterARN: *service.ClusterArn,
			Tags:       tagMap,
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
