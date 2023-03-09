package inventory

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/anchore-ecs-inventory/internal/logger"
)

func setupLogger() {
	// TODO(bradjones) Setting up logging for tests like this isn't great so will change this later
	logConfig := logger.LogConfig{
		Level: "debug",
	}
	logger.InitLogger(logConfig)
}

func TestGetInventoryReportForCluster(t *testing.T) {
	setupLogger()

	mockSvc := &mockECSClient{}

	report, err := GetInventoryReportForCluster("cluster-1", mockSvc)

	assert.NoError(t, err)
	assert.Equal(t, 3, len(report.Results[0].Images))
}