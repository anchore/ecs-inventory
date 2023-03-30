package inventory

import (
	"testing"

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
