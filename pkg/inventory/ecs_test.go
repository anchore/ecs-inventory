package inventory

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/ecs/ecsiface"
	"github.com/stretchr/testify/assert"
)

type mockECSClient struct {
	ecsiface.ECSAPI
}

func (m *mockECSClient) ListClusters(*ecs.ListClustersInput) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{
		ClusterArns: []*string{
			aws.String("arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1"),
			aws.String("arn:aws:ecs:us-east-1:123456789012:cluster/cluster-2"),
		},
	}, nil
}

func (m *mockECSClient) ListTasks(*ecs.ListTasksInput) (*ecs.ListTasksOutput, error) {
	return &ecs.ListTasksOutput{
		TaskArns: []*string{
			aws.String("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000"),
			aws.String("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111"),
		},
	}, nil
}

func (m *mockECSClient) DescribeTasks(*ecs.DescribeTasksInput) (*ecs.DescribeTasksOutput, error) {
	return &ecs.DescribeTasksOutput{
		Tasks: []*ecs.Task{
			{
				TaskArn: aws.String("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000"),
				Containers: []*ecs.Container{
					{
						Name:        aws.String("container-1"),
						Image:       aws.String("image-1"),
						ImageDigest: aws.String("sha256:1234567890123456789012345678901234567890123456789012345678901111"),
					},
					{
						Name:        aws.String("container-2"),
						Image:       aws.String("image-2"),
						ImageDigest: aws.String("sha256:1234567890123456789012345678901234567890123456789012345678902222"),
					},
				},
			},
			{
				TaskArn: aws.String("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111"),
				Containers: []*ecs.Container{
					{
						Name:        aws.String("container-3"),
						Image:       aws.String("image-3"),
						ImageDigest: aws.String("sha256:1234567890123456789012345678901234567890123456789012345678903333"),
					},
					{
						Name:        aws.String("container-4-(same-image-as-3)"),
						Image:       aws.String("image-3"),
						ImageDigest: aws.String("sha256:1234567890123456789012345678901234567890123456789012345678903333"),
					},
				},
			},
		},
	}, nil
}

func TestFetchClusters(t *testing.T) {
	mockSvc := &mockECSClient{}

	clusters, err := fetchClusters(mockSvc)

	assert.NoError(t, err)
	assert.Equal(t, 2, len(clusters))
}

func TestFetchTasksFromCluster(t *testing.T) {
	mockSvc := &mockECSClient{}

	tasks, err := fetchTasksFromCluster(mockSvc, "cluster-1")

	assert.NoError(t, err)
	assert.Equal(t, 2, len(tasks))
}

func TestFetchImagesFromTasks(t *testing.T) {
	mockSvc := &mockECSClient{}

	images, err := fetchImagesFromTasks(mockSvc, "cluster-1", []*string{
		aws.String("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000"),
		aws.String("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111"),
	})

	assert.NoError(t, err)
	assert.Equal(t, 3, len(images))
}
