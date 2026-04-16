package healthreporter

import (
	"encoding/json"
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
	UUID                 string           `json:"uuid,omitempty"`
	ProtocolVersion      int              `json:"protocol_version,omitempty"`
	Timestamp            jstime.Datetime  `json:"timestamp,omitempty"`
	Uptime               *jstime.Duration `json:"uptime,omitempty"`
	HealthReportInterval int              `json:"health_report_interval,omitempty"`
	HealthData           HealthData       `json:"health_data,omitempty"`
}

type HealthData struct {
	Type    string             `json:"type,omitempty"`
	Version int                `json:"version,omitempty"`
	Errors  HealthReportErrors `json:"errors,omitempty"`
	// ECS-specific: latest inventory reports per account/region
	AccountECSInventoryReports AccountECSInventoryReports `json:"account_ecs_inventory_reports,omitempty"`
}

type HealthReportErrors []string

// AccountECSInventoryReports holds per account information about latest inventory reports from the same batch set
type AccountECSInventoryReports map[string]InventoryReportInfo

type InventoryReportInfo struct {
	ReportTimestamp     string      `json:"report_timestamp"`
	Account             string      `json:"account_name"`
	Region              string      `json:"region"`
	SentAsUser          string      `json:"sent_as_user"`
	BatchSize           int         `json:"batch_size"`
	LastSuccessfulIndex int         `json:"last_successful_index"`
	HasErrors           bool        `json:"has_errors"`
	Batches             []BatchInfo `json:"batches"`
}

type BatchInfo struct {
	BatchIndex    int             `json:"batch_index,omitempty"`
	SendTimestamp jstime.Datetime `json:"send_timestamp,omitempty"`
	Error         string          `json:"error,omitempty"`
}

// GatedReportInfo The go routine that generates the inventory report must inform the go routine
// that sends health reports about the *latest* sent inventory reports.
// We use a map (keyed by account) to store information about the latest sent inventory
// reports. This map is shared by the go routine that generates inventory reports and the go
// routine that sends health reports. Access to the map is coordinated by a mutex.
type GatedReportInfo struct {
	AccessGate              sync.RWMutex
	AccountInventoryReports AccountECSInventoryReports
}

type _NewUUID func() uuid.UUID
type _Now func() time.Time

func GetGatedReportInfo() *GatedReportInfo {
	return &GatedReportInfo{
		AccountInventoryReports: make(AccountECSInventoryReports),
	}
}

func PeriodicallySendHealthReport(cfg *config.AppConfig, ch intg.Channels, gatedReportInfo *GatedReportInfo) {
	// Wait for registration with Enterprise to be completed
	integration := <-ch.IntegrationObj
	logger.Log.Info("Health reporting started")

	ticker := time.NewTicker(time.Duration(cfg.HealthReportIntervalSeconds) * time.Second)

	for {
		logger.Log.Infof("Waiting %d seconds to send health report...", cfg.HealthReportIntervalSeconds)

		_, _ = sendHealthReport(cfg, integration, gatedReportInfo, uuid.New, time.Now)
		<-ticker.C
	}
}

func sendHealthReport(cfg *config.AppConfig, integration *intg.Integration, gatedReportInfo *GatedReportInfo, newUUID _NewUUID, _now _Now) (*HealthReport, error) {
	healthReportID := newUUID().String()
	lastReports := GetAccountReportInfoNoBlocking(gatedReportInfo, cfg, _now)

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
			Errors:                     make(HealthReportErrors, 0),
			AccountECSInventoryReports: lastReports,
		},
		HealthReportInterval: cfg.HealthReportIntervalSeconds,
	}

	logger.Log.Infof("Sending health report (uuid:%s) covering %d accounts", healthReport.UUID, len(healthReport.HealthData.AccountECSInventoryReports))
	requestBody, err := json.Marshal(healthReport)
	if err != nil {
		logger.Log.Errorf("failed to serialize health report as JSON: %v", err)
		return nil, err
	}
	_, err = anchore.Post(requestBody, integration.UUID, HealthReportAPIPathV2, cfg.AnchoreDetails, "health report")
	if err != nil {
		logger.Log.Errorf("Failed to send health report to Anchore: %v", err)
		return nil, err
	}
	return &healthReport, nil
}

func GetAccountReportInfoNoBlocking(gatedReportInfo *GatedReportInfo, cfg *config.AppConfig, _now _Now) AccountECSInventoryReports {
	locked := gatedReportInfo.AccessGate.TryLock()

	if locked {
		defer gatedReportInfo.AccessGate.Unlock()

		logger.Log.Debugf("Removing inventory report info for accounts that are no longer active")
		accountsToRemove := make(map[string]bool)
		now := _now().UTC()
		inactiveAge := 2 * float64(cfg.PollingIntervalSeconds)

		for account, reportInfo := range gatedReportInfo.AccountInventoryReports {
			for _, batchInfo := range reportInfo.Batches {
				logger.Log.Debugf("Last inv.report (time:%s, account:%s, batch:%d/%d, sent:%s error:'%s')",
					reportInfo.ReportTimestamp, account, batchInfo.BatchIndex, reportInfo.BatchSize,
					batchInfo.SendTimestamp, batchInfo.Error)
				reportTime, err := time.Parse(time.RFC3339, reportInfo.ReportTimestamp)
				if err != nil {
					logger.Log.Errorf("failed to parse report_timestamp: %v", err)
					continue
				}
				if now.Sub(reportTime).Seconds() > inactiveAge {
					accountsToRemove[account] = true
				}
			}
		}

		for accountToRemove := range accountsToRemove {
			logger.Log.Debugf("Accounts no longer considered active: %s", accountToRemove)
			delete(gatedReportInfo.AccountInventoryReports, accountToRemove)
		}

		return gatedReportInfo.AccountInventoryReports
	}
	logger.Log.Debugf("Unable to obtain mutex lock to get account inventory report information. Continuing.")
	return AccountECSInventoryReports{}
}

func SetReportInfoNoBlocking(accountName string, count int, reportInfo InventoryReportInfo, gatedReportInfo *GatedReportInfo) {
	logger.Log.Debugf("Setting report (%s) for account name '%s': %d/%d %s %s", reportInfo.ReportTimestamp, accountName,
		reportInfo.Batches[count].BatchIndex, reportInfo.BatchSize, reportInfo.Batches[count].SendTimestamp,
		reportInfo.Batches[count].Error)
	locked := gatedReportInfo.AccessGate.TryLock()
	if locked {
		defer gatedReportInfo.AccessGate.Unlock()
		gatedReportInfo.AccountInventoryReports[accountName] = reportInfo
	} else {
		// we prioritize no blocking over actually bookkeeping info for every sent inventory report
		logger.Log.Debugf("Unable to obtain mutex lock to include inventory report timestamped %s for %s: %d/%d %s in health report. Continuing.",
			reportInfo.ReportTimestamp, accountName, reportInfo.Batches[count].BatchIndex, reportInfo.BatchSize,
			reportInfo.Batches[count].SendTimestamp)
	}
}
