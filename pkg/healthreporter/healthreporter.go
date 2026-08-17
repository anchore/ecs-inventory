// Package healthreporter periodically tells Anchore Enterprise how this agent's
// inventory reporting is going, per ECS cluster.
package healthreporter

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/anchore/ecs-inventory/internal/anchore"
	"github.com/anchore/ecs-inventory/internal/config"
	"github.com/anchore/ecs-inventory/internal/logger"
	jstime "github.com/anchore/ecs-inventory/internal/time"
	intg "github.com/anchore/ecs-inventory/pkg/integration"
)

const healthProtocolVersion = 1
const healthDataVersion = 1
const healthDataType = "ecs_inventory_agent"
const HealthReportAPIPathV2 = "v2/system/integrations/{{id}}/health-report"

type HealthReport struct {
	UUID                 string           `json:"uuid,omitempty"`                   // uuid for this health report
	ProtocolVersion      int              `json:"protocol_version,omitempty"`       // protocol version for the "common" part of health reporting
	Timestamp            jstime.Datetime  `json:"timestamp,omitempty"`              // timestamp for this health report in UTC().Format(time.RFC3339)
	Uptime               *jstime.Duration `json:"uptime,omitempty"`                 // running time of integration instance
	HealthReportInterval int              `json:"health_report_interval,omitempty"` // time in seconds between health reports
	HealthData           HealthData       `json:"health_data,omitempty"`            // ecs-inventory agent specific health data
}

type HealthData struct {
	Type    string             `json:"type,omitempty"`    // type of health data
	Version int                `json:"version,omitempty"` // format version
	Errors  HealthReportErrors `json:"errors,omitempty"`  // list of errors
	// Anything below this line is specific to the ecs-inventory agent.
	//
	// Unlike the k8s agent, which reports one result per account, the ECS agent sweeps
	// many clusters within a single account and sends one inventory report per cluster,
	// so each account maps to a list of per-cluster results. A flat, k8s-shaped map
	// would hide the failures of all but one cluster.
	AccountECSInventoryReports AccountECSInventoryReports `json:"account_ecs_inventory_reports,omitempty"`
}

type HealthReportErrors []string

// AccountECSInventoryReports holds, per account, the latest inventory report result
// for each ECS cluster.
type AccountECSInventoryReports map[string][]InventoryReportInfo

// InventoryReportInfo is one ECS cluster's inventory send.
//
// Note the deliberate absence of omitempty on most fields: Enterprise requires them
// all, and the zero values (has_errors: false, last_successful_index: -1) are
// meaningful rather than absent.
type InventoryReportInfo struct {
	ReportTimestamp     string      `json:"report_timestamp"`      // Timestamp of the inventory report that was sent
	Account             string      `json:"account_name"`          // Name of the account the inventory report belongs to
	SentAsUser          string      `json:"sent_as_user"`          // User that the inventory report was sent as
	BatchSize           int         `json:"batch_size"`            // Number of batches the inventory report was sent in (always 1 for ECS)
	LastSuccessfulIndex int         `json:"last_successful_index"` // Index of the last successfully sent batch, -1 if none
	HasErrors           bool        `json:"has_errors"`            // True if any of the batches had an error
	ClusterARN          string      `json:"cluster_arn"`           // ARN of the ECS cluster this report covers
	Region              string      `json:"region,omitempty"`      // AWS region the cluster was found in
	Batches             []BatchInfo `json:"batches"`               // Information about each inventory report batch
}

type BatchInfo struct {
	BatchIndex    int             `json:"batch_index,omitempty"`    // 1-based index of this inventory report batch item
	SendTimestamp jstime.Datetime `json:"send_timestamp,omitempty"` // Timestamp when the batch was sent, in UTC().Format(time.RFC3339)
	Error         string          `json:"error,omitempty"`          // Any error this batch encountered when sent
}

// GatedReportInfo carries the latest per-cluster inventory results from the goroutine
// that generates inventory reports to the goroutine that sends health reports.
//
// A buffered channel would be the obvious choice, but it is FIFO and refuses writes
// when full, so a burst would drop the *newest* results — exactly the ones a health
// report wants. A map behind a mutex drops the oldest instead, and neither side ever
// blocks on the other (see the TryLock use below).
//
// It is keyed account -> cluster ARN so that each poll cycle replaces a cluster's
// entry rather than accumulating duplicates.
type GatedReportInfo struct {
	AccessGate              sync.RWMutex
	AccountInventoryReports map[string]map[string]InventoryReportInfo
	// region -> the failure that stopped the agent collecting anything at all for that
	// region on the most recent poll cycle. Unlike per-cluster results these are not
	// pruned on age: every poll cycle either sets or clears the region's entry.
	regionErrors map[string]string
}

type _NewUUID func() uuid.UUID

type _Now func() time.Time

func GetGatedReportInfo() *GatedReportInfo {
	return &GatedReportInfo{
		AccountInventoryReports: make(map[string]map[string]InventoryReportInfo),
		regionErrors:            make(map[string]string),
	}
}

// PeriodicallySendHealthReport blocks until registration with Enterprise completes,
// then sends a health report every cfg.HealthReportIntervalSeconds.
//
// If registration never succeeds the integration channel is closed without a value,
// and health reporting stays off for the life of the process.
func PeriodicallySendHealthReport(cfg *config.AppConfig, ch intg.Channels, gatedReportInfo *GatedReportInfo) {
	// Wait for registration with Enterprise to be completed
	integration := <-ch.IntegrationObj
	if integration == nil {
		logger.Log.Info("Health reporting not started, this agent is not registered with Anchore")
		return
	}
	logger.Log.Info("Health reporting started", "intervalSeconds", cfg.HealthReportIntervalSeconds)

	ticker := time.NewTicker(time.Duration(cfg.HealthReportIntervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		_, _ = sendHealthReport(cfg, integration, gatedReportInfo, uuid.New, time.Now)
		<-ticker.C
	}
}

// sendHealthReport sends one health report. It returns (nil, nil) when the report was
// deliberately skipped because the inventory results could not be read without blocking.
func sendHealthReport(cfg *config.AppConfig, integration *intg.Integration, gatedReportInfo *GatedReportInfo,
	newUUID _NewUUID, _now _Now,
) (*HealthReport, error) {
	healthReportID := newUUID().String()
	lastReports, reportErrors, ok := GetHealthDataNoBlocking(gatedReportInfo, cfg, _now)
	if !ok {
		// Sending anyway would mean sending a report with no results and no errors,
		// which Enterprise reads as healthy. Skipping instead leaves the previous
		// report standing until the next interval, a few seconds away.
		logger.Log.Info("Skipping health report, inventory results are being written right now")
		return nil, nil
	}

	now := _now().UTC()
	integration.Uptime = &jstime.Duration{Duration: now.Sub(integration.StartedAt.Time)}
	healthReport := HealthReport{
		UUID:            healthReportID,
		ProtocolVersion: healthProtocolVersion,
		Timestamp:       jstime.Datetime{Time: now},
		Uptime:          integration.Uptime,
		HealthData: HealthData{
			Type:                       healthDataType,
			Version:                    healthDataVersion,
			Errors:                     reportErrors,
			AccountECSInventoryReports: lastReports,
		},
		HealthReportInterval: cfg.HealthReportIntervalSeconds,
	}

	logger.Log.Info("Sending health report", "uuid", healthReport.UUID,
		"accounts", len(healthReport.HealthData.AccountECSInventoryReports),
		"errors", len(healthReport.HealthData.Errors))

	requestBody, err := json.Marshal(healthReport)
	if err != nil {
		logger.Log.Error("Failed to serialize health report as JSON", err)
		return nil, err
	}

	if _, err := anchore.Post(requestBody, integration.UUID, HealthReportAPIPathV2, cfg.AnchoreDetails, "health report"); err != nil {
		switch {
		case anchore.UserLacksAPIPrivileges(err):
			logger.Log.Error("Failed to send health report, the configured user lacks the reportHealth permission", err)
		default:
			logger.Log.Error("Failed to send health report to Anchore", err)
		}
		return nil, err
	}
	return &healthReport, nil
}

// GetHealthDataNoBlocking returns the latest per-cluster inventory results, flattened
// into the shape Enterprise expects and with clusters that have not been seen recently
// enough dropped, along with any region-wide errors recorded since the last report.
//
// It never blocks: if the lock is held by the inventory goroutine it reports that it
// could not read the data rather than waiting for it. The caller must not treat that as
// "no results and no errors" — an empty health report positively asserts health to
// Enterprise, which would briefly paper over an ongoing failure.
func GetHealthDataNoBlocking(gatedReportInfo *GatedReportInfo, cfg *config.AppConfig, _now _Now) (AccountECSInventoryReports, HealthReportErrors, bool) {
	if !gatedReportInfo.AccessGate.TryLock() {
		logger.Log.Debug("Unable to obtain mutex lock to get account inventory report information. Continuing.")
		return nil, nil, false
	}
	defer gatedReportInfo.AccessGate.Unlock()

	pruneInactiveClusters(gatedReportInfo, cfg, _now)

	reports := make(AccountECSInventoryReports, len(gatedReportInfo.AccountInventoryReports))
	for account, clusterReports := range gatedReportInfo.AccountInventoryReports {
		infos := make([]InventoryReportInfo, 0, len(clusterReports))
		for _, info := range clusterReports {
			infos = append(infos, info)
		}
		// map iteration order is random; sort so successive reports for the same set of
		// clusters are diffable
		sort.Slice(infos, func(i, j int) bool { return infos[i].ClusterARN < infos[j].ClusterARN })
		reports[account] = infos
	}

	reportErrors := make(HealthReportErrors, 0, len(gatedReportInfo.regionErrors))
	for _, message := range gatedReportInfo.regionErrors {
		reportErrors = append(reportErrors, message)
	}
	sort.Strings(reportErrors)

	return reports, reportErrors, true
}

// pruneInactiveClusters drops clusters whose last inventory report is older than two
// polling intervals. This is how a deleted or renamed ECS cluster ages out of the
// health report instead of being reported forever.
//
// The caller must hold the access gate.
func pruneInactiveClusters(gatedReportInfo *GatedReportInfo, cfg *config.AppConfig, _now _Now) {
	now := _now().UTC()
	inactiveAge := 2 * float64(cfg.PollingIntervalSeconds)

	for account, clusterReports := range gatedReportInfo.AccountInventoryReports {
		for clusterARN, info := range clusterReports {
			reportTime, err := time.Parse(time.RFC3339, info.ReportTimestamp)
			if err != nil {
				logger.Log.Error("Failed to parse report_timestamp, dropping cluster from health report", err,
					"cluster", clusterARN, "reportTimestamp", info.ReportTimestamp)
				delete(clusterReports, clusterARN)
				continue
			}
			if now.Sub(reportTime).Seconds() > inactiveAge {
				logger.Log.Debug("Cluster no longer considered active", "account", account, "cluster", clusterARN)
				delete(clusterReports, clusterARN)
			}
		}
		if len(clusterReports) == 0 {
			delete(gatedReportInfo.AccountInventoryReports, account)
		}
	}
}

// SetReportInfosNoBlocking records a whole poll cycle's per-cluster results in one
// shot.
//
// The ECS agent fans out one goroutine per cluster, so writing per cluster would have
// those goroutines contend on the gate and silently drop most of them; the caller
// collects results first and writes them here once.
func SetReportInfosNoBlocking(accountName string, infos []InventoryReportInfo, gatedReportInfo *GatedReportInfo) {
	if !gatedReportInfo.AccessGate.TryLock() {
		// we prioritize not blocking over bookkeeping info for every sent inventory report
		logger.Log.Debug("Unable to obtain mutex lock to include inventory reports in health report. Continuing.",
			"account", accountName, "clusters", len(infos))
		return
	}
	defer gatedReportInfo.AccessGate.Unlock()

	clusterReports, ok := gatedReportInfo.AccountInventoryReports[accountName]
	if !ok {
		clusterReports = make(map[string]InventoryReportInfo, len(infos))
		gatedReportInfo.AccountInventoryReports[accountName] = clusterReports
	}

	for _, info := range infos {
		logger.Log.Debug("Setting inventory report info", "account", accountName, "cluster", info.ClusterARN,
			"reportTimestamp", info.ReportTimestamp, "hasErrors", info.HasErrors)
		clusterReports[info.ClusterARN] = info
	}
}

// SetRegionErrorNoBlocking records a failure that stopped the agent collecting any
// inventory at all for a region — expired AWS credentials, a revoked ecs:ListClusters,
// a bad region. A nil err clears any previously recorded failure.
//
// Such a failure produces no per-cluster results, so without this the existing entries
// would simply age out and the integration would report itself perfectly healthy while
// collecting nothing. Enterprise copies health_data.errors straight into the
// integration's health report, and a non-empty list is what marks it UNHEALTHY.
func SetRegionErrorNoBlocking(region string, err error, gatedReportInfo *GatedReportInfo) {
	if !gatedReportInfo.AccessGate.TryLock() {
		logger.Log.Debug("Unable to obtain mutex lock to record region status in health report. Continuing.",
			"region", region)
		return
	}
	defer gatedReportInfo.AccessGate.Unlock()

	if err == nil {
		delete(gatedReportInfo.regionErrors, region)
		return
	}

	message := fmt.Sprintf("failed to collect ECS inventory for region %s: %s", region, err)
	logger.Log.Debug("Recording region failure in health report", "region", region, "err", err)
	gatedReportInfo.regionErrors[region] = message
}
