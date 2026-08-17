package healthreporter

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/h2non/gock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/ecs-inventory/internal/config"
	"github.com/anchore/ecs-inventory/internal/logger"
	jstime "github.com/anchore/ecs-inventory/internal/time"
	"github.com/anchore/ecs-inventory/pkg/connection"
	intg "github.com/anchore/ecs-inventory/pkg/integration"
)

func init() {
	logger.Log = &logger.NoOpLogger{}
}

const (
	clusterA = "arn:aws:ecs:us-east-1:123456789012:cluster/cluster-a"
	clusterB = "arn:aws:ecs:us-east-1:123456789012:cluster/cluster-b"
)

var (
	fixedNow  = time.Date(2024, time.April, 10, 12, 14, 16, 0, time.UTC)
	fixedUUID = uuid.MustParse("11111111-2222-3333-4444-555555555555")
)

func testNow() time.Time { return fixedNow }

func testUUID() uuid.UUID { return fixedUUID }

func testConfig() *config.AppConfig {
	return &config.AppConfig{
		PollingIntervalSeconds:      300,
		HealthReportIntervalSeconds: 60,
		AnchoreDetails: connection.AnchoreInfo{
			URL:      "https://ancho.re",
			User:     "admin",
			Password: "foobar",
			Account:  "test-account",
			HTTP: connection.HTTPConfig{
				TimeoutSeconds: 10,
				Insecure:       true,
			},
		},
	}
}

func healthyInfo(cluster string) InventoryReportInfo {
	return InventoryReportInfo{
		ReportTimestamp:     fixedNow.Format(time.RFC3339),
		Account:             "test-account",
		SentAsUser:          "admin",
		BatchSize:           1,
		LastSuccessfulIndex: 1,
		HasErrors:           false,
		ClusterARN:          cluster,
		Region:              "us-east-1",
		Batches: []BatchInfo{
			{BatchIndex: 1, SendTimestamp: jstime.Datetime{Time: fixedNow}},
		},
	}
}

func failedInfo(cluster string) InventoryReportInfo {
	return InventoryReportInfo{
		ReportTimestamp:     fixedNow.Format(time.RFC3339),
		Account:             "test-account",
		SentAsUser:          "admin",
		BatchSize:           1,
		LastSuccessfulIndex: -1,
		HasErrors:           true,
		ClusterARN:          cluster,
		Region:              "us-east-1",
		Batches: []BatchInfo{
			{BatchIndex: 1, SendTimestamp: jstime.Datetime{Time: fixedNow}, Error: "unable to report Inventory to Anchore"},
		},
	}
}

// The expected wire format. Enterprise requires report_timestamp, account_name,
// sent_as_user, batch_size, last_successful_index, has_errors, batches and cluster_arn
// on every entry, and batches must be a list rather than null, so this asserts on an
// exact string rather than a round trip.
const expectedHealthReportJSON = `{` +
	`"uuid":"11111111-2222-3333-4444-555555555555",` +
	`"protocol_version":1,` +
	`"timestamp":"2024-04-10T12:14:16Z",` +
	`"uptime":600.000000,` +
	`"health_report_interval":60,` +
	`"health_data":{` +
	`"type":"ecs_inventory_agent",` +
	`"version":1,` +
	`"account_ecs_inventory_reports":{` +
	`"test-account":[` +
	`{"report_timestamp":"2024-04-10T12:14:16Z","account_name":"test-account","sent_as_user":"admin",` +
	`"batch_size":1,"last_successful_index":1,"has_errors":false,` +
	`"cluster_arn":"arn:aws:ecs:us-east-1:123456789012:cluster/cluster-a","region":"us-east-1",` +
	`"batches":[{"batch_index":1,"send_timestamp":"2024-04-10T12:14:16Z"}]},` +
	`{"report_timestamp":"2024-04-10T12:14:16Z","account_name":"test-account","sent_as_user":"admin",` +
	`"batch_size":1,"last_successful_index":-1,"has_errors":true,` +
	`"cluster_arn":"arn:aws:ecs:us-east-1:123456789012:cluster/cluster-b","region":"us-east-1",` +
	`"batches":[{"batch_index":1,"send_timestamp":"2024-04-10T12:14:16Z",` +
	`"error":"unable to report Inventory to Anchore"}]}` +
	`]}}}`

func testIntegration() *intg.Integration {
	return &intg.Integration{
		UUID:      "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		Type:      "ecs_inventory_agent",
		StartedAt: jstime.Datetime{Time: fixedNow.Add(-10 * time.Minute)},
	}
}

func TestHealthReportMarshalling(t *testing.T) {
	defer gock.Off()
	gock.New("https://ancho.re").
		Post("/v2/system/integrations/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/health-report").
		Reply(201).
		BodyString("")

	gated := GetGatedReportInfo()
	SetReportInfosNoBlocking("test-account", []InventoryReportInfo{healthyInfo(clusterA), failedInfo(clusterB)}, gated)

	report, err := sendHealthReport(testConfig(), testIntegration(), gated, testUUID, testNow)
	require.NoError(t, err)

	got, err := json.Marshal(report)
	require.NoError(t, err)

	// exact match, so that field presence, field order and the float encoding of uptime
	// are all pinned
	assert.Equal(t, expectedHealthReportJSON, string(got))
}

func TestSendHealthReport(t *testing.T) {
	defer gock.Off()

	var sentBody map[string]interface{}
	gock.New("https://ancho.re").
		Post("/v2/system/integrations/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/health-report").
		MatchHeader("x-anchore-account", "test-account").
		BasicAuth("admin", "foobar").
		AddMatcher(func(req *http.Request, _ *gock.Request) (bool, error) {
			return true, json.NewDecoder(req.Body).Decode(&sentBody)
		}).
		Reply(201).
		BodyString("")

	gated := GetGatedReportInfo()
	SetReportInfosNoBlocking("test-account", []InventoryReportInfo{healthyInfo(clusterA)}, gated)

	report, err := sendHealthReport(testConfig(), testIntegration(), gated, testUUID, testNow)

	require.NoError(t, err)
	assert.True(t, gock.IsDone())
	assert.Equal(t, fixedUUID.String(), report.UUID)
	assert.Equal(t, 10*time.Minute, report.Uptime.Duration)
	assert.Equal(t, "ecs_inventory_agent", sentBody["health_data"].(map[string]interface{})["type"])
}

func TestSendHealthReportError(t *testing.T) {
	for _, status := range []int{403, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			defer gock.Off()
			gock.New("https://ancho.re").
				Post("/v2/system/integrations/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/health-report").
				Reply(status).
				JSON(map[string]interface{}{
					"message":  "Not authorized. Requires permissions: action=reportHealth",
					"detail":   map[string]interface{}{},
					"httpcode": status,
				})

			report, err := sendHealthReport(testConfig(), testIntegration(), GetGatedReportInfo(), testUUID, testNow)

			assert.Error(t, err)
			assert.Nil(t, report)
		})
	}
}

func TestSetAndGetReportInfosRoundTrip(t *testing.T) {
	gated := GetGatedReportInfo()
	cfg := testConfig()

	SetReportInfosNoBlocking("test-account", []InventoryReportInfo{healthyInfo(clusterA), healthyInfo(clusterB)}, gated)

	got, _, _ := GetHealthDataNoBlocking(gated, cfg, testNow)

	require.Len(t, got["test-account"], 2)
	assert.Equal(t, clusterA, got["test-account"][0].ClusterARN)
	assert.Equal(t, clusterB, got["test-account"][1].ClusterARN)
}

func TestSetReportInfosReplacesPerCluster(t *testing.T) {
	gated := GetGatedReportInfo()
	cfg := testConfig()

	SetReportInfosNoBlocking("test-account", []InventoryReportInfo{healthyInfo(clusterA)}, gated)
	SetReportInfosNoBlocking("test-account", []InventoryReportInfo{failedInfo(clusterA)}, gated)

	got, _, _ := GetHealthDataNoBlocking(gated, cfg, testNow)

	require.Len(t, got["test-account"], 1, "a second cycle must replace, not duplicate, a cluster's entry")
	assert.True(t, got["test-account"][0].HasErrors)
}

func TestGetAccountReportInfoPrunesInactiveClusters(t *testing.T) {
	gated := GetGatedReportInfo()
	cfg := testConfig() // polling interval 300s, so anything older than 600s is inactive

	stale := healthyInfo(clusterA)
	stale.ReportTimestamp = fixedNow.Add(-601 * time.Second).Format(time.RFC3339)
	fresh := healthyInfo(clusterB)

	SetReportInfosNoBlocking("test-account", []InventoryReportInfo{stale, fresh}, gated)

	got, _, _ := GetHealthDataNoBlocking(gated, cfg, testNow)

	require.Len(t, got["test-account"], 1)
	assert.Equal(t, clusterB, got["test-account"][0].ClusterARN)
}

func TestGetAccountReportInfoDropsEmptyAccounts(t *testing.T) {
	gated := GetGatedReportInfo()
	cfg := testConfig()

	stale := healthyInfo(clusterA)
	stale.ReportTimestamp = fixedNow.Add(-601 * time.Second).Format(time.RFC3339)
	SetReportInfosNoBlocking("test-account", []InventoryReportInfo{stale}, gated)

	got, _, _ := GetHealthDataNoBlocking(gated, cfg, testNow)

	assert.Empty(t, got)
	assert.NotContains(t, got, "test-account")
	assert.Empty(t, gated.AccountInventoryReports, "an account with no active clusters should be removed")
}

func TestGetAccountReportInfoDropsUnparsableTimestamps(t *testing.T) {
	gated := GetGatedReportInfo()
	cfg := testConfig()

	bad := healthyInfo(clusterA)
	bad.ReportTimestamp = "not-a-timestamp"
	SetReportInfosNoBlocking("test-account", []InventoryReportInfo{bad}, gated)

	got, _, _ := GetHealthDataNoBlocking(gated, cfg, testNow)

	assert.Empty(t, got)
}

func TestGetHealthDataNoBlockingDoesNotBlock(t *testing.T) {
	gated := GetGatedReportInfo()
	gated.AccessGate.Lock()
	defer gated.AccessGate.Unlock()

	done := make(chan bool, 1)
	go func() {
		_, _, ok := GetHealthDataNoBlocking(gated, testConfig(), testNow)
		done <- ok
	}()

	select {
	case ok := <-done:
		assert.False(t, ok, "contention must be reported rather than looking like an empty result set")
	case <-time.After(2 * time.Second):
		t.Fatal("GetHealthDataNoBlocking blocked while the access gate was held")
	}
}

// An empty health report positively asserts health to Enterprise, so a report that
// could not read the inventory results must not be sent at all.
func TestSendHealthReportSkippedWhenDataIsContended(t *testing.T) {
	defer gock.Off()
	gock.New("https://ancho.re").
		Post("/v2/system/integrations/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/health-report").
		Reply(201).
		BodyString("")

	gated := GetGatedReportInfo()
	SetRegionErrorNoBlocking("us-east-1", errors.New("expired credentials"), gated)
	gated.AccessGate.Lock()
	defer gated.AccessGate.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		report, err := sendHealthReport(testConfig(), testIntegration(), gated, testUUID, testNow)
		assert.NoError(t, err)
		assert.Nil(t, report)
	}()

	select {
	case <-done:
		assert.False(t, gock.IsDone(), "no health report should have been sent")
	case <-time.After(2 * time.Second):
		t.Fatal("sendHealthReport blocked while the access gate was held")
	}
}

// A failure that stops the agent collecting anything for a region produces no
// per-cluster results, so it has to reach health_data.errors or the integration reads
// as HEALTHY while gathering nothing at all.
func TestSetRegionErrorSurfacesInHealthData(t *testing.T) {
	gated := GetGatedReportInfo()
	cfg := testConfig()

	SetRegionErrorNoBlocking("us-east-1", errors.New("expired credentials"), gated)

	_, gotErrors, _ := GetHealthDataNoBlocking(gated, cfg, testNow)

	require.Len(t, gotErrors, 1)
	assert.Equal(t, "failed to collect ECS inventory for region us-east-1: expired credentials", gotErrors[0])
}

func TestSetRegionErrorClearedByNilError(t *testing.T) {
	gated := GetGatedReportInfo()
	cfg := testConfig()

	SetRegionErrorNoBlocking("us-east-1", errors.New("expired credentials"), gated)
	SetRegionErrorNoBlocking("us-east-1", nil, gated)

	_, gotErrors, _ := GetHealthDataNoBlocking(gated, cfg, testNow)

	assert.Empty(t, gotErrors)
}

func TestSetRegionErrorReplacesPreviousError(t *testing.T) {
	gated := GetGatedReportInfo()
	cfg := testConfig()

	SetRegionErrorNoBlocking("us-east-1", errors.New("first"), gated)
	SetRegionErrorNoBlocking("us-east-1", errors.New("second"), gated)

	_, gotErrors, _ := GetHealthDataNoBlocking(gated, cfg, testNow)

	require.Len(t, gotErrors, 1, "a region only ever has one current failure")
	assert.Contains(t, gotErrors[0], "second")
}

func TestSetRegionErrorNoBlockingDoesNotBlock(t *testing.T) {
	gated := GetGatedReportInfo()
	gated.AccessGate.Lock()

	done := make(chan struct{})
	go func() {
		SetRegionErrorNoBlocking("us-east-1", errors.New("expired credentials"), gated)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		gated.AccessGate.Unlock()
		t.Fatal("SetRegionErrorNoBlocking blocked while the access gate was held")
	}

	gated.AccessGate.Unlock()
	assert.Empty(t, gated.regionErrors, "nothing should have been written while the gate was held")
}

// The region error has to survive all the way onto the wire, where Enterprise copies
// health_data.errors straight into the integration's health report.
func TestSendHealthReportIncludesRegionErrors(t *testing.T) {
	defer gock.Off()

	var sentBody map[string]interface{}
	gock.New("https://ancho.re").
		Post("/v2/system/integrations/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/health-report").
		AddMatcher(func(req *http.Request, _ *gock.Request) (bool, error) {
			return true, json.NewDecoder(req.Body).Decode(&sentBody)
		}).
		Reply(201).
		BodyString("")

	gated := GetGatedReportInfo()
	SetRegionErrorNoBlocking("us-east-1", errors.New("operation error ECS: ListClusters, access denied"), gated)

	report, err := sendHealthReport(testConfig(), testIntegration(), gated, testUUID, testNow)

	require.NoError(t, err)
	require.Len(t, report.HealthData.Errors, 1)

	healthData, ok := sentBody["health_data"].(map[string]interface{})
	require.True(t, ok)
	sentErrors, ok := healthData["errors"].([]interface{})
	require.True(t, ok, "errors must reach Enterprise, it is what marks the integration unhealthy")
	require.Len(t, sentErrors, 1)
	assert.Contains(t, sentErrors[0], "ListClusters")
	assert.Empty(t, healthData["account_ecs_inventory_reports"],
		"a region-wide failure yields no per-cluster results")
}

// An empty error list must not marshal to null: Enterprise treats errors as optional,
// but a present-and-null value is not the same as absent.
func TestHealthDataOmitsEmptyErrors(t *testing.T) {
	defer gock.Off()
	gock.New("https://ancho.re").
		Post("/v2/system/integrations/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/health-report").
		Reply(201).
		BodyString("")

	gated := GetGatedReportInfo()
	SetReportInfosNoBlocking("test-account", []InventoryReportInfo{healthyInfo(clusterA)}, gated)

	report, err := sendHealthReport(testConfig(), testIntegration(), gated, testUUID, testNow)
	require.NoError(t, err)

	got, err := json.Marshal(report)
	require.NoError(t, err)
	assert.NotContains(t, string(got), `"errors"`)
}

func TestSetReportInfosNoBlockingDoesNotBlock(t *testing.T) {
	gated := GetGatedReportInfo()
	gated.AccessGate.Lock()

	done := make(chan struct{})
	go func() {
		SetReportInfosNoBlocking("test-account", []InventoryReportInfo{healthyInfo(clusterA)}, gated)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		gated.AccessGate.Unlock()
		t.Fatal("SetReportInfosNoBlocking blocked while the access gate was held")
	}

	gated.AccessGate.Unlock()
	assert.Empty(t, gated.AccountInventoryReports, "nothing should have been written while the gate was held")
}

func TestPeriodicallySendHealthReportStopsWhenNotRegistered(t *testing.T) {
	ch := intg.GetChannels()
	close(ch.IntegrationObj)

	done := make(chan struct{})
	go func() {
		PeriodicallySendHealthReport(testConfig(), ch, GetGatedReportInfo())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("health reporting should stop when registration never produced an integration")
	}
}
