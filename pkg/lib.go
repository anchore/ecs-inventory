package pkg

import (
	"time"

	"github.com/anchore/ecs-inventory/internal/config"
	"github.com/anchore/ecs-inventory/internal/logger"
	jstime "github.com/anchore/ecs-inventory/internal/time"
	"github.com/anchore/ecs-inventory/pkg/connection"
	"github.com/anchore/ecs-inventory/pkg/healthreporter"
	"github.com/anchore/ecs-inventory/pkg/integration"
	"github.com/anchore/ecs-inventory/pkg/inventory"
	pkgLogger "github.com/anchore/ecs-inventory/pkg/logger"
)

var log pkgLogger.Logger

// PeriodicallyGetInventoryReport periodically retrieves image results with channel-based coordination
// for health reporting integration. Waits for registration to complete before starting.
// Note: Errors do not cause the function to exit, since this is periodically running.
func PeriodicallyGetInventoryReport(
	cfg *config.AppConfig,
	ch integration.Channels,
	gatedReportInfo *healthreporter.GatedReportInfo,
) {
	// Wait for registration with Enterprise to be disabled or completed
	<-ch.InventoryReportingEnabled
	logger.Log.Info("Inventory reporting started")
	healthReportingEnabled := false

	// Fire off a ticker that reports according to a configurable polling interval
	ticker := time.NewTicker(time.Duration(cfg.PollingIntervalSeconds) * time.Second)

	for {
		reportTimestamp := time.Now().UTC().Format(time.RFC3339)
		err := inventory.GetInventoryReportsForRegion(cfg.Region, cfg.AnchoreDetails, cfg.Quiet, cfg.DryRun)
		if err != nil {
			logger.Log.Error("Failed to get Inventory Reports for region", err)
		} else {
			// Track batch info for health reporting
			reportInfo := healthreporter.InventoryReportInfo{
				Account:             cfg.AnchoreDetails.Account,
				Region:              cfg.Region,
				BatchSize:           1,
				LastSuccessfulIndex: 1,
				Batches:             make([]healthreporter.BatchInfo, 0),
				HasErrors:           false,
				ReportTimestamp:     reportTimestamp,
			}
			batchInfo := healthreporter.BatchInfo{
				SendTimestamp: jstime.Datetime{Time: time.Now().UTC()},
				BatchIndex:    1,
			}
			reportInfo.Batches = append(reportInfo.Batches, batchInfo)

			select {
			case isEnabled, isNotClosed := <-ch.HealthReportingEnabled:
				if isNotClosed {
					healthReportingEnabled = isEnabled
				}
				logger.Log.Infof("Health reporting enabled: %t", healthReportingEnabled)
			default:
			}
			if healthReportingEnabled {
				healthreporter.SetReportInfoNoBlocking(cfg.AnchoreDetails.Account, 0, reportInfo, gatedReportInfo)
			}
		}

		logger.Log.Infof("Waiting %d seconds for next poll...", cfg.PollingIntervalSeconds)

		// Wait at least as long as the ticker
		logger.Log.Debugf("Start new gather: %s", <-ticker.C)
	}
}

// PeriodicallyGetInventoryReportSimple is the simple polling loop used when Anchore details
// are not configured (no health reporting or registration).
// Note: Errors do not cause the function to exit, since this is periodically running.
func PeriodicallyGetInventoryReportSimple(
	pollingIntervalSeconds int,
	anchoreDetails connection.AnchoreInfo,
	region string,
	quiet, dryRun bool,
) {
	// Fire off a ticker that reports according to a configurable polling interval
	ticker := time.NewTicker(time.Duration(pollingIntervalSeconds) * time.Second)

	for {
		err := inventory.GetInventoryReportsForRegion(region, anchoreDetails, quiet, dryRun)
		if err != nil {
			logger.Log.Error("Failed to get Inventory Reports for region", err)
		}

		// Wait at least as long as the ticker
		logger.Log.Debugf("Start new gather %s", <-ticker.C)
	}
}

func SetLogger(l pkgLogger.Logger) {
	log = l
}
