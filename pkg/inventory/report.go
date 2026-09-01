package inventory

import (
	"context"
	"encoding/json"
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
		logger.Log.Info("Reporting results to Anchore")
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

// BuildAWSConfig loads the AWS config for a region and, when assumeRoleARN is set, swaps in an STS
// assume-role credentials cache. The credentials cache resolves credentials lazily and refreshes
// them automatically as they expire. Build it once and reuse the returned config across poll cycles
// so that refresh actually happens over the daemon's lifetime instead of issuing a fresh AssumeRole
// every cycle. The role may live in the same or a different AWS account.
func BuildAWSConfig(ctx context.Context, region, assumeRoleARN, externalID string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load aws config: %w", err)
	}

	cfg, assumed := configureAssumeRole(cfg, assumeRoleARN, externalID)
	if assumed {
		logger.Log.Info("Assuming IAM role for ECS inventory", "roleArn", assumeRoleARN)
	}
	return cfg, nil
}

// configureAssumeRole replaces cfg's credentials with an STS assume-role credentials cache when
// assumeRoleARN is set, reporting whether it did. When assumeRoleARN is empty cfg is returned
// unchanged so the agent's ambient credentials are used.
func configureAssumeRole(cfg aws.Config, assumeRoleARN, externalID string) (aws.Config, bool) {
	if assumeRoleARN == "" {
		return cfg, false
	}
	stsClient := sts.NewFromConfig(cfg)
	provider := stscreds.NewAssumeRoleProvider(stsClient, assumeRoleARN, assumeRoleOptionsFor(externalID))
	cfg.Credentials = aws.NewCredentialsCache(provider)
	return cfg, true
}

// assumeRoleOptionsFor returns a function that configures an STS AssumeRoleProvider with the app's
// session name and, when non-empty, the given external ID (required by some cross-account trust
// policies).
func assumeRoleOptionsFor(externalID string) func(*stscreds.AssumeRoleOptions) {
	return func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = internal.ApplicationName
		if externalID != "" {
			o.ExternalID = aws.String(externalID)
		}
	}
}

// AppendAssumedRole adds an "assumedRole" key/value to structured log attributes when the pass is
// assuming a role, so log lines make clear which role (and therefore which account) the work is
// happening under. When assumeRoleARN is empty the agent is using its own ambient credentials and
// nothing is added. It is the single source of truth for this attribute across packages (the poll
// loop's passLogAttrs delegates to it).
func AppendAssumedRole(attrs []interface{}, assumeRoleARN string) []interface{} {
	if assumeRoleARN != "" {
		attrs = append(attrs, "assumedRole", assumeRoleARN)
	}
	return attrs
}

// GetInventoryReportsForRegion collects inventory reports using the supplied AWS config, which the
// caller builds once (via BuildAWSConfig) and reuses across poll cycles. assumeRoleARN is the role
// this pass assumes (empty when using the agent's own credentials) and is included in log lines so
// the region and role a report came from are unambiguous. The region is read from cfg.Region -- the
// region the AWS SDK actually resolved and will query -- so log/tracker text can never disagree with
// where the calls really went (e.g. when the region came from AWS_REGION or instance metadata).
func GetInventoryReportsForRegion(cfg aws.Config, assumeRoleARN string, anchoreDetails connection.AnchoreInfo, quiet, dryRun bool) error {
	ctx := context.Background()
	region := cfg.Region
	defer tracker.TrackFunctionTime(time.Now(), fmt.Sprintf("Getting Inventory Reports for region: %s", region))
	logger.Log.Info("Getting Inventory Reports for region", AppendAssumedRole([]interface{}{"region", region}, assumeRoleARN)...)

	// Credentials are validated once at startup (see pkg.preparePasses); any credential problem that
	// develops afterward surfaces through the ECS API calls below and is logged/retried per cycle, so
	// we don't re-check them here.
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
			report, err := GetInventoryReportForCluster(ctx, cluster, ecsClient, assumeRoleARN)
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

// GetInventoryReportForCluster is an atomic method for getting in-use image results, for a cluster.
// assumeRoleARN (empty when using the agent's own credentials) is included in result log lines so
// it is clear which assumed role surfaced the cluster's containers.
func GetInventoryReportForCluster(ctx context.Context, clusterARN string, ecsClient ECSAPI, assumeRoleARN string) (reporter.Report, error) {
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
		logger.Log.Info("Found containers in cluster",
			AppendAssumedRole([]interface{}{"cluster", clusterARN, "containerCount", len(containers)}, assumeRoleARN)...)
	}

	return ensureReferencedObjectsExist(report), nil
}
