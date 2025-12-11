package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecs"

	"github.com/anchore/ecs-inventory/internal/logger"
	"github.com/anchore/ecs-inventory/internal/tracker"
	"github.com/anchore/ecs-inventory/pkg/connection"
	"github.com/anchore/ecs-inventory/pkg/reporter"
)

func reportToStdout(report reporter.Report) error {
	enc := json.NewEncoder(os.Stdout)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("unable to show inventory: %w", err)
	}
	return nil
}

func HandleReport(report reporter.Report, anchoreDetails connection.AnchoreInfo, quiet, dryRun bool) error {
	switch {
	case dryRun:
		logger.Log.Info("Dry run specified, not reporting inventory")
	case anchoreDetails.IsValid():
		if err := reporter.Post(report, anchoreDetails); err != nil {
			return fmt.Errorf("unable to report Inventory to Anchore: %w", err)
		}
	default:
		logger.Log.Warn("Anchore details not specified, not reporting inventory")
	}

	if !quiet {
		return reportToStdout(report)
	}
	return nil
}

// GetInventoryReportsForRegion collects inventory reports for a specified region.
func GetInventoryReportsForRegion(region string, anchoreDetails connection.AnchoreInfo, quiet, dryRun bool) error {
	ctx := context.Background()
	defer tracker.TrackFunctionTime(time.Now(), fmt.Sprintf("Getting Inventory Reports for region: %s", region))
	logger.Log.Info("Getting Inventory Reports for region", "region", region)

	// Load AWS config
	opts := []func(*config.LoadOptions) error{}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		logger.Log.Error("Failed to load AWS config", err)
		return fmt.Errorf("failed to load aws config: %w", err)
	}

	err = checkAWSCredentials(ctx, cfg)
	if err != nil {
		return err
	}

	ecsClient := ecs.NewFromConfig(cfg)

	clusters, err := fetchClusters(ctx, ecsClient)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(len(clusters))

	for _, cluster := range clusters {
		// capture cluster value
		go func(cluster string) {
			defer wg.Done()

			// You can reuse ecsClient; keeping same behavior as before
			report, err := GetInventoryReportForCluster(ctx, cluster, ecsClient)
			if err != nil {
				logger.Log.Error("Failed to get inventory report for cluster", err)
			}

			// Only report if there are containers present in the cluster
			if len(report.Containers) != 0 {
				err = HandleReport(report, anchoreDetails, quiet, dryRun)
				if err != nil {
					logger.Log.Error("Failed to report inventory for cluster", err)
					jsonReport, _ := json.Marshal(report)
					logger.Log.Error("Failed payload", fmt.Errorf("report %s", jsonReport))
				}
			}
		}(cluster)
	}

	wg.Wait()
	return nil
}

// ensures that the referenced objects in the report exist, and if not, creates them.
// e.g. if a service is referenced in a task, but the service is not present in the report, create the service with minimal metadata
//
// NOTE: in the future, this can be removed if the enterprise API is updated to accept reports with missing objects and create them on
// the server side
func ensureReferencedObjectsExist(report reporter.Report) reporter.Report {
	updatedReport := report

	serviceARNs := map[string]bool{}
	for _, service := range report.Services {
		serviceARNs[service.ARN] = true
	}

	taskARNs := map[string]bool{}
	for _, task := range report.Tasks {
		taskARNs[task.ARN] = true
	}

	// Ensure all services referenced in tasks exist in the report
	for _, task := range report.Tasks {
		if task.ServiceARN != "" {
			if _, ok := serviceARNs[task.ServiceARN]; !ok {
				// Service not present in report, create it
				updatedReport.Services = append(updatedReport.Services, reporter.Service{
					ARN: task.ServiceARN,
				})
				logger.Log.Warn(
					"Service referenced in task not present in report, adding minimal service to report",
					"service",
					task.ServiceARN,
				)
			}
		}
	}

	// Ensure all tasks referenced in containers exist in the report
	for _, container := range report.Containers {
		if _, ok := taskARNs[container.TaskARN]; !ok {
			// Task not present in report, create it
			updatedReport.Tasks = append(updatedReport.Tasks, reporter.Task{
				ARN:        container.TaskARN,
				TaskDefARN: "UNKNOWN", // NOTE TaskDefARN is not a nullable field in the db, so we need to provide a value
				ServiceARN: "",
			})
			logger.Log.Warn(
				"Task referenced in container not present in report, adding minimal task to report",
				"task",
				container.TaskARN,
			)
		}
	}

	// If the report has services, ensure tasks that are not part of a service reference an "UNKNOWN" placeholder service
	// so the enterprise API will accept the report
	addUnknownService := false
	if len(report.Services) > 0 {
		for i, task := range updatedReport.Tasks {
			if task.ServiceARN == "" {
				updatedReport.Tasks[i].ServiceARN = "UNKNOWN"
				if !addUnknownService {
					updatedReport.Services = append(updatedReport.Services, reporter.Service{
						ARN: "UNKNOWN",
					})
					addUnknownService = true
				}
			}
		}
	}

	return updatedReport
}

// GetInventoryReportForCluster is an atomic method for getting in-use image results, for a cluster
func GetInventoryReportForCluster(ctx context.Context, clusterARN string, ecsClient ECSAPI) (reporter.Report, error) {
	defer tracker.TrackFunctionTime(time.Now(), fmt.Sprintf("Getting Inventory Report for cluster: %s", clusterARN))
	logger.Log.Debug("Found cluster", "cluster", clusterARN)

	report := reporter.Report{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		ClusterARN: clusterARN,
	}
	tasks, err := fetchTasksFromCluster(ctx, ecsClient, clusterARN)
	if err != nil {
		return reporter.Report{}, err
	}

	servicesMeta := []reporter.Service{}
	services, err := fetchServicesFromCluster(ctx, ecsClient, clusterARN)
	if err != nil {
		return reporter.Report{}, err
	}
	if len(services) == 0 {
		logger.Log.Debug("No services found in cluster", "cluster", clusterARN)
	} else {
		servicesMeta, err = fetchServicesMetadata(ctx, ecsClient, clusterARN, services)
		if err != nil {
			return reporter.Report{}, err
		}
	}
	report.Services = servicesMeta

	// Must be at least one task to continue
	if len(tasks) == 0 {
		logger.Log.Debug("No tasks found in cluster", "cluster", clusterARN)
	} else {
		logger.Log.Debug("Found tasks in cluster", "cluster", clusterARN, "taskCount", len(tasks))

		taskMeta, err := fetchTasksMetadata(ctx, ecsClient, clusterARN, tasks)
		if err != nil {
			return reporter.Report{}, err
		}
		report.Tasks = taskMeta

		containers, err := fetchContainersFromTasks(ctx, ecsClient, clusterARN, tasks)
		if err != nil {
			return reporter.Report{}, err
		}
		report.Containers = containers
		logger.Log.Info("Found containers in cluster", "cluster", clusterARN, "containerCount", len(containers))
	}

	return ensureReferencedObjectsExist(report), nil
}
