package pkg

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/ecs-inventory/internal/config"
	"github.com/anchore/ecs-inventory/pkg/connection"
	"github.com/anchore/ecs-inventory/pkg/healthreporter"
	"github.com/anchore/ecs-inventory/pkg/integration"
	"github.com/anchore/ecs-inventory/pkg/logger"
)

type mockLogger struct{}

func (m *mockLogger) Error(msg string, err error, args ...interface{}) {}
func (m *mockLogger) Warn(msg string, args ...interface{})             {}
func (m *mockLogger) Warnf(msg string, args ...interface{})            {}
func (m *mockLogger) Info(msg string, args ...interface{})             {}
func (m *mockLogger) Debug(msg string, args ...interface{})            {}
func (m *mockLogger) Debugf(msg string, args ...interface{})           {}

func TestSetLogger(t *testing.T) {
	mock := &mockLogger{}
	SetLogger(mock)
	assert.Equal(t, logger.Logger(mock), log)
}

var testAnchoreDetails = connection.AnchoreInfo{
	URL:     "https://ancho.re",
	User:    "admin",
	Account: "test-account",
}

func testAppConfig() *config.AppConfig {
	return &config.AppConfig{PollingIntervalSeconds: 300}
}

// stubCollector replaces the AWS-facing collector for the duration of a test.
func stubCollector(t *testing.T, collect func(region string) ([]healthreporter.InventoryReportInfo, error)) {
	t.Helper()
	original := getInventoryReportsForRegion
	t.Cleanup(func() { getInventoryReportsForRegion = original })
	getInventoryReportsForRegion = func(region string, _ connection.AnchoreInfo, _, _ bool) ([]healthreporter.InventoryReportInfo, error) {
		return collect(region)
	}
}

func clusterInfo(clusterARN string) healthreporter.InventoryReportInfo {
	return healthreporter.InventoryReportInfo{
		ReportTimestamp:     time.Now().UTC().Format(time.RFC3339),
		Account:             testAnchoreDetails.Account,
		SentAsUser:          testAnchoreDetails.User,
		ClusterARN:          clusterARN,
		Region:              "us-east-1",
		BatchSize:           1,
		LastSuccessfulIndex: 1,
		Batches:             make([]healthreporter.BatchInfo, 0, 1),
	}
}

func healthData(t *testing.T, gated *healthreporter.GatedReportInfo) (healthreporter.AccountECSInventoryReports, healthreporter.HealthReportErrors) {
	t.Helper()
	reports, reportErrors, ok := healthreporter.GetHealthDataNoBlocking(gated, testAppConfig(), time.Now)
	require.True(t, ok)
	return reports, reportErrors
}

func newLoop(gated *healthreporter.GatedReportInfo, ch integration.Channels) *inventoryLoop {
	return &inventoryLoop{
		anchoreDetails:  testAnchoreDetails,
		region:          "us-east-1",
		quiet:           true,
		ch:              ch,
		gatedReportInfo: gated,
	}
}

// Nothing is recorded for the health report until registration says health reporting is
// on; until then the inventory reports themselves still go out.
func TestInventoryLoopRecordsNothingUntilHealthReportingIsEnabled(t *testing.T) {
	SetLogger(&mockLogger{})
	collected := 0
	stubCollector(t, func(string) ([]healthreporter.InventoryReportInfo, error) {
		collected++
		return []healthreporter.InventoryReportInfo{clusterInfo("cluster-a")}, nil
	})

	gated := healthreporter.GetGatedReportInfo()
	loop := newLoop(gated, integration.GetChannels())

	loop.runOnce()

	assert.Equal(t, 1, collected, "inventory reporting must run regardless of health reporting")
	reports, reportErrors := healthData(t, gated)
	assert.Empty(t, reports)
	assert.Empty(t, reportErrors)
}

func TestInventoryLoopRecordsResultsOnceHealthReportingIsEnabled(t *testing.T) {
	SetLogger(&mockLogger{})
	stubCollector(t, func(string) ([]healthreporter.InventoryReportInfo, error) {
		return []healthreporter.InventoryReportInfo{clusterInfo("cluster-a")}, nil
	})

	gated := healthreporter.GetGatedReportInfo()
	ch := integration.GetChannels()
	ch.HealthReportingEnabled <- true

	loop := newLoop(gated, ch)
	loop.runOnce()

	reports, reportErrors := healthData(t, gated)
	require.Len(t, reports[testAnchoreDetails.Account], 1)
	assert.Equal(t, "cluster-a", reports[testAnchoreDetails.Account][0].ClusterARN)
	assert.Empty(t, reportErrors)
}

// A failure that stops the agent collecting anything for the region produces no
// per-cluster results, so it has to reach the health report by the region-error path or
// the integration reads as healthy while collecting nothing.
func TestInventoryLoopReportsAndClearsRegionFailures(t *testing.T) {
	SetLogger(&mockLogger{})
	var collectErr error
	stubCollector(t, func(string) ([]healthreporter.InventoryReportInfo, error) {
		if collectErr != nil {
			return nil, collectErr
		}
		return []healthreporter.InventoryReportInfo{clusterInfo("cluster-a")}, nil
	})

	gated := healthreporter.GetGatedReportInfo()
	ch := integration.GetChannels()
	ch.HealthReportingEnabled <- true
	loop := newLoop(gated, ch)

	collectErr = errors.New("ExpiredToken: the security token included in the request is expired")
	loop.runOnce()

	_, reportErrors := healthData(t, gated)
	require.Len(t, reportErrors, 1)
	assert.Contains(t, reportErrors[0], "us-east-1")
	assert.Contains(t, reportErrors[0], "ExpiredToken")

	// the next successful cycle clears it again
	collectErr = nil
	loop.runOnce()

	_, reportErrors = healthData(t, gated)
	assert.Empty(t, reportErrors)
}

// PerformRegistration closes the channels when it is done, so every cycle after
// registration finishes reads from a closed channel. That must not be mistaken for
// health reporting having been turned off.
func TestInventoryLoopKeepsReportingAfterTheEnableChannelCloses(t *testing.T) {
	SetLogger(&mockLogger{})
	cluster := "cluster-a"
	stubCollector(t, func(string) ([]healthreporter.InventoryReportInfo, error) {
		return []healthreporter.InventoryReportInfo{clusterInfo(cluster)}, nil
	})

	gated := healthreporter.GetGatedReportInfo()
	ch := integration.GetChannels()
	ch.HealthReportingEnabled <- true
	loop := newLoop(gated, ch)

	loop.runOnce()
	close(ch.HealthReportingEnabled)

	cluster = "cluster-b"
	loop.runOnce()

	reports, _ := healthData(t, gated)
	require.Len(t, reports[testAnchoreDetails.Account], 2)
	assert.Equal(t, "cluster-a", reports[testAnchoreDetails.Account][0].ClusterARN)
	assert.Equal(t, "cluster-b", reports[testAnchoreDetails.Account][1].ClusterARN)
}

// Registration signals this channel before it starts talking to Enterprise; an
// unreachable Enterprise must not hold up inventory reporting forever, but a cycle must
// not start before the signal either (dry-run and unsupported-Enterprise runs both rely
// on the signal to decide whether health reporting is on).
func TestPeriodicallyGetInventoryReportWaitsForTheGoAhead(t *testing.T) {
	SetLogger(&mockLogger{})
	collected := make(chan string, 1)
	stubCollector(t, func(region string) ([]healthreporter.InventoryReportInfo, error) {
		collected <- region
		return nil, nil
	})

	ch := integration.GetChannels()
	// a polling interval long enough that the loop performs exactly one cycle and then
	// parks on the ticker for the rest of the test binary's life
	go PeriodicallyGetInventoryReport(3600, testAnchoreDetails, "us-east-1", true, false,
		ch, healthreporter.GetGatedReportInfo())

	select {
	case region := <-collected:
		t.Fatalf("collected inventory for %s before inventory reporting was enabled", region)
	case <-time.After(100 * time.Millisecond):
	}

	ch.InventoryReportingEnabled <- true

	select {
	case region := <-collected:
		assert.Equal(t, "us-east-1", region)
	case <-time.After(10 * time.Second):
		t.Fatal("inventory was never collected after inventory reporting was enabled")
	}
}
