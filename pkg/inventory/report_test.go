package inventory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetInventoryReportForCluster(t *testing.T) {
	mockSvc := &mockECSClient{}

	report, err := GetInventoryReportForCluster("cluster-1", mockSvc)

	assert.NoError(t, err)
	assert.Equal(t, 4, len(report.Containers))
}
