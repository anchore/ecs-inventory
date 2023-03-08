package inventory

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
)

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
