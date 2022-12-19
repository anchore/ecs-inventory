package ecg

import (
	"fmt"
	"os"
	"time"

	"github.com/anchore/elastic-container-gatherer/ecg/inventory"
	"github.com/anchore/elastic-container-gatherer/ecg/logger"
	"github.com/anchore/elastic-container-gatherer/ecg/presenter"
	"github.com/anchore/elastic-container-gatherer/ecg/reporter"
	"github.com/anchore/elastic-container-gatherer/internal/config"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
)

var log logger.Logger

func HandleReport(report inventory.Report, cfg *config.Application) error {
	if cfg.AnchoreDetails.IsValid() {
		if err := reporter.Post(report, cfg.AnchoreDetails, cfg); err != nil {
			return fmt.Errorf("unable to report Inventory to Anchore: %w", err)
		}
	} else {
		log.Debug("Anchore details not specified, not reporting inventory")
	}

	if err := presenter.GetPresenter(cfg.PresenterOpt, report).Present(os.Stdout); err != nil {
		return fmt.Errorf("unable to show inventory: %w", err)
	}
	return nil
}

// PeriodicallyGetInventoryReport periodically retrieve image results and report/output them according to the configuration.
// Note: Errors do not cause the function to exit, since this is periodically running
func PeriodicallyGetInventoryReport(cfg *config.Application) {
	// Fire off a ticker that reports according to a configurable polling interval
	ticker := time.NewTicker(time.Duration(cfg.PollingIntervalSeconds) * time.Second)

	for {
		report, err := GetInventoryReport(cfg)
		if err != nil {
			log.Error("Failed to get Inventory Report", err)
		} else {
			err := HandleReport(report, cfg)
			if err != nil {
				log.Error("Failed to handle Inventory Report", err)
			}
		}

		// Wait at least as long as the ticker
		log.Debug("Start new gather", <-ticker.C)
	}
}

// GetInventoryReport is an atomic method for getting in-use image results, in parallel for multiple clusters
func GetInventoryReport(cfg *config.Application) (inventory.Report, error) {
	sessConfig := &aws.Config{}
	if cfg.Region != "" {
		sessConfig.Region = aws.String(cfg.Region)
	}
	sess, err := session.NewSession(sessConfig)
	if err != nil {
		log.Error("Failed to create AWS session", err)
	}

	err = checkAWSCredentials(sess)
	if err != nil {
		return inventory.Report{}, err
	}

	return inventory.Report{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Results:       []inventory.ReportItem{},
		InventoryType: "ecs",
	}, nil
}

func SetLogger(logger logger.Logger) {
	log = logger
}

// Check if AWS are present, should be stored in ~/.aws/credentials
func checkAWSCredentials(sess *session.Session) error {
	_, err := sess.Config.Credentials.Get()
	if err != nil {
		// TODO: Add some logs here detailing where to put the credentials
		return fmt.Errorf("unable to get AWS credentials: %w", err)
	}
	return nil
}
