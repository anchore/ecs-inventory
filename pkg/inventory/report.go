package inventory

import (
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecs"

	"github.com/anchore/anchore-ecs-inventory/internal/logger"
)

type Report struct {
	Timestamp     string       `json:"timestamp,omitempty"` // Should be generated using time.Now.UTC() and formatted according to RFC Y-M-DTH:M:SZ
	Results       []ReportItem `json:"results"`
	ClusterName   string       `json:"cluster_name,omitempty"` // NOTE: The key here is ClusterName to match the Anchore API but it's actually the region
	InventoryType string       `json:"inventory_type"`
}

// GetInventoryReport is an atomic method for getting in-use image results, in parallel for multiple clusters
func GetInventoryReport(region string) (Report, error) {
	sessConfig := &aws.Config{}
	if region != "" {
		sessConfig.Region = aws.String(region)
	}
	sess, err := session.NewSession(sessConfig)
	if err != nil {
		logger.Log.Error("Failed to create AWS session", err)
	}

	err = checkAWSCredentials(sess)
	if err != nil {
		return Report{}, err
	}

	ecsClient := ecs.New(sess)

	clusters, err := fetchClusters(ecsClient)
	if err != nil {
		return Report{}, err
	}

	results := []ReportItem{}

	for _, cluster := range clusters {
		logger.Log.Debug("Found cluster", "cluster", *cluster)

		// Fetch tasks in cluster
		tasks, err := fetchTasksFromCluster(ecsClient, *cluster)
		if err != nil {
			return Report{}, err
		}

		images := []ReportImage{}
		// Must be at least one task to continue
		if len(tasks) == 0 {
			logger.Log.Debug("No tasks found in cluster", "cluster", *cluster)
		} else {
			images, err = fetchImagesFromTasks(ecsClient, *cluster, tasks)
			if err != nil {
				return Report{}, err
			}
		}

		results = append(results, ReportItem{
			Namespace: *cluster, // NOTE The key is Namespace to match the Anchore API but it's actually the cluster ARN
			Images:    images,
		})
	}
	// NOTE: clusterName not used for ECS as the clusternARN (used as the namespace in results payload) provides sufficient
	// unique location data (account, region, clustername)
	return Report{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Results:       results,
		ClusterName:   "",
		InventoryType: "ecs",
	}, nil
}
