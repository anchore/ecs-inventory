package ecg

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/anchore/anchore-ecs-inventory/ecg/connection"
	"github.com/anchore/anchore-ecs-inventory/ecg/inventory"
	"github.com/anchore/anchore-ecs-inventory/ecg/logger"
	"github.com/anchore/anchore-ecs-inventory/ecg/reporter"
)

var log logger.Logger

// Output the JSON formatted report to stdout
func reportToStdout(report inventory.Report) error {
	enc := json.NewEncoder(os.Stdout)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("unable to show inventory: %w", err)
	}
	return nil
}

func HandleReport(report inventory.Report, anchoreDetails connection.AnchoreInfo) error {
	if anchoreDetails.IsValid() {
		if err := reporter.Post(report, anchoreDetails); err != nil {
			return fmt.Errorf("unable to report Inventory to Anchore: %w", err)
		}
	} else {
		log.Debug("Anchore details not specified, not reporting inventory")
	}

	// Encode the report to JSON and output to stdout (maintains same behaviour as when multiple presenters were supported)
	return reportToStdout(report)
}

// PeriodicallyGetInventoryReport periodically retrieve image results and report/output them according to the configuration.
// Note: Errors do not cause the function to exit, since this is periodically running
func PeriodicallyGetInventoryReport(pollingIntervalSeconds int, anchoreDetails connection.AnchoreInfo, region string) {
	// Fire off a ticker that reports according to a configurable polling interval
	ticker := time.NewTicker(time.Duration(pollingIntervalSeconds) * time.Second)

	for {
		report, err := inventory.GetInventoryReport(region)
		if err != nil {
			log.Error("Failed to get Inventory Report", err)
		} else {
			err := HandleReport(report, anchoreDetails)
			if err != nil {
				log.Error("Failed to handle Inventory Report", err)
			}
		}

		// Wait at least as long as the ticker
		log.Debugf("Start new gather %s", <-ticker.C)
	}
}

func SetLogger(logger logger.Logger) {
	log = logger
}
