package pkg

import (
	"time"

	"github.com/anchore/ecs-inventory/pkg/connection"
	"github.com/anchore/ecs-inventory/pkg/healthreporter"
	"github.com/anchore/ecs-inventory/pkg/integration"
	"github.com/anchore/ecs-inventory/pkg/inventory"
	"github.com/anchore/ecs-inventory/pkg/logger"
)

var log logger.Logger

// swapped out in tests so the loop's wiring can be exercised without AWS
var getInventoryReportsForRegion = inventory.GetInventoryReportsForRegion

// PeriodicallyGetInventoryReport periodically retrieve image results and report/output them according to the configuration.
// Note: Errors do not cause the function to exit, since this is periodically running
func PeriodicallyGetInventoryReport(
	pollingIntervalSeconds int,
	anchoreDetails connection.AnchoreInfo,
	region string,
	quiet, dryRun bool,
	ch integration.Channels,
	gatedReportInfo *healthreporter.GatedReportInfo,
) {
	// Wait for the go-ahead. Registration signals this before it starts talking to
	// Enterprise, so an unreachable Enterprise delays health reporting but never
	// inventory reporting.
	<-ch.InventoryReportingEnabled

	loop := &inventoryLoop{
		anchoreDetails:  anchoreDetails,
		region:          region,
		quiet:           quiet,
		dryRun:          dryRun,
		ch:              ch,
		gatedReportInfo: gatedReportInfo,
	}

	// Fire off a ticker that reports according to a configurable polling interval
	ticker := time.NewTicker(time.Duration(pollingIntervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		loop.runOnce()

		// Wait at least as long as the ticker
		log.Debugf("Start new gather %s", <-ticker.C)
	}
}

// inventoryLoop is the state PeriodicallyGetInventoryReport carries between polls,
// extracted so that a single cycle can be driven in a test.
type inventoryLoop struct {
	anchoreDetails  connection.AnchoreInfo
	region          string
	quiet, dryRun   bool
	ch              integration.Channels
	gatedReportInfo *healthreporter.GatedReportInfo

	healthReportingEnabled bool
}

// runOnce collects the region's inventory, sends it, and records what happened for the
// next health report.
func (l *inventoryLoop) runOnce() {
	infos, err := getInventoryReportsForRegion(l.region, l.anchoreDetails, l.quiet, l.dryRun)
	if err != nil {
		log.Error("Failed to get Inventory Reports for region", err)
	}

	// Non-blocking read: registration completes on its own schedule, and this loop
	// must not wait on it
	select {
	case isEnabled, isNotClosed := <-l.ch.HealthReportingEnabled:
		if isNotClosed {
			l.healthReportingEnabled = isEnabled
		}
		// a closed channel means registration has finished for good, not that health
		// reporting was turned off, so the last value read stands
	default:
	}

	if !l.healthReportingEnabled {
		return
	}

	// A region-wide failure yields no per-cluster results at all, so it has to be
	// reported separately or the integration reads as healthy while collecting
	// nothing. A nil err clears the previous cycle's failure.
	healthreporter.SetRegionErrorNoBlocking(l.region, err, l.gatedReportInfo)

	if len(infos) > 0 {
		healthreporter.SetReportInfosNoBlocking(l.anchoreDetails.Account, infos, l.gatedReportInfo)
	}
}

func SetLogger(logger logger.Logger) {
	log = logger
}
