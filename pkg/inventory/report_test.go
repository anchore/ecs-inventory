package inventory

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetInventoryReportForCluster(t *testing.T) {
	mockSvc := &mockECSClient{}

	report, err := GetInventoryReportForCluster("cluster-1", mockSvc)

	assert.NoError(t, err)
	fmt.Println(report)
	// assert.Equal(t, 3, len(report.Containers))
}
