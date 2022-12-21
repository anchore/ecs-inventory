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
	"github.com/aws/aws-sdk-go/service/ecs"
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

	ecsClient := ecs.New(sess)

	clusters, err := fetchClusters(ecsClient)
	if err != nil {
		return inventory.Report{}, err
	}

	results := []inventory.ReportItem{}

	for _, cluster := range clusters {
		log.Debug("Found cluster", "cluster", *cluster)

		// Fetch tasks in cluster
		tasks, err := fetchTasksFromCluster(ecsClient, *cluster)
		if err != nil {
			return inventory.Report{}, err
		}
		images, err := fetchImagesFromTasks(ecsClient, *cluster, tasks)

		results = append(results, inventory.ReportItem{
			Namespace: *cluster, //NOTE The key is Namespace to match the Anchore API but it's actually the cluster ARN
			Images:    images,
		})
	}

	return inventory.Report{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Results:       results,
		ClusterName:   cfg.Region, // NOTE: The key here is ClusterName to match the Anchore API but it's actually the region
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

func fetchClusters(client *ecs.ECS) ([]*string, error) {
	input := &ecs.ListClustersInput{}

	result, err := client.ListClusters(input)
	if err != nil {
		return nil, err
	}

	return result.ClusterArns, nil
}

func fetchTasksFromCluster(client *ecs.ECS, cluster string) ([]*string, error) {
	input := &ecs.ListTasksInput{
		Cluster: aws.String(cluster),
	}

	result, err := client.ListTasks(input)
	if err != nil {
		return nil, err
	}

	return result.TaskArns, nil
}

func fetchImagesFromTasks(client *ecs.ECS, cluster string, tasks []*string) ([]inventory.ReportImage, error) {
	input := &ecs.DescribeTasksInput{
		Cluster: aws.String(cluster),
		Tasks:   tasks,
	}

	results, err := client.DescribeTasks(input)
	if err != nil {
		return []inventory.ReportImage{}, err
	}

	uniqueImages := make(map[string]inventory.ReportImage)

	for _, task := range results.Tasks {
		for _, container := range task.Containers {
			digest := ""
			if container.ImageDigest != nil {
				digest = *container.ImageDigest
			}
			uniqueName := fmt.Sprintf("%s@%s", *container.Image, digest)
			uniqueImages[uniqueName] = inventory.ReportImage{
				Tag:        *container.Image,
				RepoDigest: digest,
			}
		}
	}

	// convert map of unique images to a slice
	images := []inventory.ReportImage{}
	for _, image := range uniqueImages {
		images = append(images, image)
	}

	return images, nil
}
