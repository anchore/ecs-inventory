package inventory

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/ecs/ecsiface"

	"github.com/anchore/anchore-ecs-inventory/pkg/reporter"
)

// Check if AWS are present, should be stored in ~/.aws/credentials
func checkAWSCredentials(sess *session.Session) error {
	_, err := sess.Config.Credentials.Get()
	if err != nil {
		// TODO: Add some logs here detailing where to put the credentials
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

func fetchImagesFromTasks(client ecsiface.ECSAPI, cluster string, tasks []*string) ([]reporter.ReportImage, error) {
	input := &ecs.DescribeTasksInput{
		Cluster: aws.String(cluster),
		Tasks:   tasks,
	}

	results, err := client.DescribeTasks(input)
	if err != nil {
		return []reporter.ReportImage{}, err
	}

	uniqueImages := make(map[string]reporter.ReportImage)

	for _, task := range results.Tasks {
		for _, container := range task.Containers {
			digest := ""
			if container.ImageDigest != nil {
				digest = *container.ImageDigest
			}
			uniqueName := fmt.Sprintf("%s@%s", *container.Image, digest)
			uniqueImages[uniqueName] = reporter.ReportImage{
				Tag:        *container.Image,
				RepoDigest: digest,
			}
		}
	}

	// convert map of unique images to a slice
	images := []reporter.ReportImage{}
	for _, image := range uniqueImages {
		images = append(images, image)
	}

	return images, nil
}
