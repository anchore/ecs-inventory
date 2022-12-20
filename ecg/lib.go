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
	"github.com/anchore/elastic-container-gatherer/internal/log"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
)

type channels struct {
	reportItem chan inventory.ReportItem
	errors     chan error
	stopper    chan struct{}
}

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
			log.Errorf("Failed to get Inventory Report: %w", err)
		} else {
			err := HandleReport(report, cfg)
			if err != nil {
				log.Errorf("Failed to handle Inventory Report: %w", err)
			}
		}

		// Wait at least as long as the ticker
		log.Debugf("Start new gather: %s", <-ticker.C)
	}
}

// GetInventoryReport is an atomic method for getting in-use image results, in parallel for multiple clusters
func GetInventoryReport(cfg *config.Application) (inventory.Report, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("eu-west-2")}, // TODO - make this configurable
	)
	if err != nil {
		log.Errorf("Failed to create AWS session: %w", err)
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
	log.Log = logger
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
