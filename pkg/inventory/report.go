package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/anchore/ecs-inventory/internal"
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

// MaxAssumeRoles bounds how many roles a single agent will assume in one poll.
// This is a deliberate product limit, not an AWS one: it is the number of roles the
// suite is tested against, and running beyond it would put customers on untested ground.
// Raising it means extending the test plan first.
const MaxAssumeRoles = 5

// AssumeRole identifies an IAM role that anchore-ecs-inventory will assume (via STS) before
// querying ECS. The role may live in the same AWS account or a different one, provided its
// trust policy permits the agent's base credentials to assume it.
type AssumeRole struct {
	ARN string `mapstructure:"arn"`
	// ExternalID is passed when assuming ARN. Some roles (commonly cross-account, third-party
	// roles) require an external ID in their trust policy. Optional.
	ExternalID string `mapstructure:"external-id"`
}

// assumeRoleOptions builds the STS assume-role options used when AssumeRoleARN is configured.
// ponytail: returned as a func rather than inlined at the call site because stscreds keeps its
// options unexported — applying this to a zero AssumeRoleOptions is the only way to assert the wiring.
func assumeRoleOptions(externalID string) func(*stscreds.AssumeRoleOptions) {
	return func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = internal.ApplicationName
		if externalID != "" {
			o.ExternalID = aws.String(externalID)
		}
	}
}

// withAssumeRole swaps cfg's credentials for STS assume-role credentials when assumeRoleARN is set,
// and returns cfg untouched when it is not. The credentials cache resolves them lazily and refreshes
// them automatically as they expire, which suits the long-running daemon. The role may live in the
// same AWS account or a different one.
// ponytail: split out of GetInventoryReportsForRegion so the credential wiring is unit testable
// without reaching AWS; that function loads real config and calls ECS.
func withAssumeRole(cfg aws.Config, assumeRoleARN, externalID string) aws.Config {
	if assumeRoleARN == "" {
		return cfg
	}
	logger.Log.Info("Assuming IAM role for ECS inventory", "roleArn", assumeRoleARN)
	provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), assumeRoleARN, assumeRoleOptions(externalID))
	cfg.Credentials = aws.NewCredentialsCache(provider)
	return cfg
}

// GetInventoryReportsForRegion collects inventory reports for a specified region.
//
// With no roles configured the agent inventories the region using its own credentials.
// With roles configured it inventories the region once per role, so a single agent can cover
// several AWS accounts. A role that fails is logged and skipped rather than aborting the poll:
// one unreachable account must not cost the customer inventory for the accounts that do work.
func GetInventoryReportsForRegion(region string, assumeRoles []AssumeRole, anchoreDetails connection.AnchoreInfo, quiet, dryRun bool) error {
	ctx := context.Background()
	defer tracker.TrackFunctionTime(time.Now(), fmt.Sprintf("Getting Inventory Reports for region: %s", region))
	logger.Log.Info("Getting Inventory Reports for region", "region", region)

	cfg, err := loadAWSConfig(ctx, region)
	if err != nil {
		return err
	}

	if len(assumeRoles) == 0 {
		return reportForCredentials(ctx, cfg, anchoreDetails, quiet, dryRun)
	}

	return reportForEachRole(assumeRoles, func(role AssumeRole) error {
		return reportForCredentials(ctx, withAssumeRole(cfg, role.ARN, role.ExternalID), anchoreDetails, quiet, dryRun)
	})
}

// reportForEachRole runs report for every configured role, continuing past failures, and returns
// the joined failures (nil if every role succeeded). Continuing matters: one account with a broken
// trust policy must not cost the customer inventory for the accounts that are working.
// ponytail: sequential — MaxAssumeRoles is 5, so the wall-clock saving from running accounts
// concurrently is not worth multiplying peak STS/ECS call volume. Revisit if the cap is raised.
// ponytail: takes report as a func so the continue-on-failure behaviour is testable without AWS.
func reportForEachRole(roles []AssumeRole, report func(AssumeRole) error) error {
	var errs []error
	for _, role := range roles {
		if err := report(role); err != nil {
			logger.Log.Error("Failed to get inventory reports for assumed role", err, "roleArn", role.ARN)
			errs = append(errs, fmt.Errorf("role %s: %w", role.ARN, err))
		}
	}
	return errors.Join(errs...)
}

// loadAWSConfig resolves the agent's own AWS config for the given region.
func loadAWSConfig(ctx context.Context, region string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		logger.Log.Error("Failed to load AWS config", err)
		return aws.Config{}, fmt.Errorf("failed to load aws config: %w", err)
	}
	return cfg, nil
}

// reportForCredentials inventories every cluster reachable with the given AWS config and reports
// it to Anchore. Split out of GetInventoryReportsForRegion so the same work can be repeated once
// per assumed role.
func reportForCredentials(ctx context.Context, cfg aws.Config, anchoreDetails connection.AnchoreInfo, quiet, dryRun bool) error {
	err := checkAWSCredentials(ctx, cfg)
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
				TaskDefARN: unknown, // NOTE TaskDefARN is not a nullable field in the db, so we need to provide a value
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
				updatedReport.Tasks[i].ServiceARN = unknown
				if !addUnknownService {
					updatedReport.Services = append(updatedReport.Services, reporter.Service{
						ARN: unknown,
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
