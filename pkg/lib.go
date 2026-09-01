package pkg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/anchore/ecs-inventory/internal/config"
	"github.com/anchore/ecs-inventory/pkg/connection"
	"github.com/anchore/ecs-inventory/pkg/inventory"
	"github.com/anchore/ecs-inventory/pkg/logger"
)

var log logger.Logger

// errMissingRegion is returned by startup validation when no AWS region can be resolved for a pass.
var errMissingRegion = errors.New("no AWS region could be resolved")

// inventoryPass describes a single account-region gather: which region to query and, optionally,
// which role to assume first.
type inventoryPass struct {
	region        string
	assumeRoleARN string
	externalID    string
}

// readyPass is an inventory pass that passed startup validation, paired with the AWS config to run
// it. For assume-role passes cfg is built once and reused so its credentials cache refreshes over
// the daemon's lifetime; for the ambient pass cfg is rebuilt each cycle (see the poll loop).
type readyPass struct {
	region        string
	assumeRoleARN string
	cfg           aws.Config
}

// awsConfigBuilder builds an aws.Config for a pass. Production uses inventory.BuildAWSConfig; tests
// inject a fake so startup validation can be exercised without real AWS calls.
type awsConfigBuilder func(ctx context.Context, region, assumeRoleARN, externalID string) (aws.Config, error)

// passLogAttrs returns structured-log attributes describing a pass: always the region, plus the
// assumed role when one is configured. The assumed-role part delegates to inventory.AppendAssumedRole
// so both packages format the attribute identically.
func passLogAttrs(region, assumeRoleARN string) []interface{} {
	return inventory.AppendAssumedRole([]interface{}{"region", region}, assumeRoleARN)
}

// preparePasses runs startup validation for every configured pass and returns the passes that are
// ready to poll, or an error if any pass fails validation. Validation is deliberately asymmetric:
//
//   - Region must be resolvable for EVERY pass. Static credentials need no region, so a missing
//     region would otherwise slip through and make every poll cycle silently fail forever while the
//     agent looks healthy. We check the region the AWS SDK actually resolved (config, flag, env, or
//     instance metadata), not just the configured value.
//   - Credentials are pre-flighted (forcing the STS AssumeRole) only for assume-role passes, so a
//     misconfigured or unauthorized role fails fast at startup. The ambient (no-role) pass is NOT
//     credential-checked here: that preserves the pre-assume-role behavior of logging and retrying
//     transient credential issues rather than exiting on a startup blip.
func preparePasses(ctx context.Context, build awsConfigBuilder, passes []inventoryPass) ([]readyPass, error) {
	ready := make([]readyPass, 0, len(passes))
	failed := 0
	for _, pass := range passes {
		cfg, err := build(ctx, pass.region, pass.assumeRoleARN, pass.externalID)
		if err != nil {
			failed++
			log.Error("Startup validation failed: unable to load AWS config for inventory pass", err,
				passLogAttrs(pass.region, pass.assumeRoleARN)...)
			continue
		}
		if cfg.Region == "" {
			failed++
			log.Error(
				"Startup validation failed: no AWS region could be resolved for inventory pass "+
					"(set a region via config, --region, ANCHORE_ECS_INVENTORY_REGION, or the assume-role entry's region)",
				errMissingRegion, passLogAttrs(pass.region, pass.assumeRoleARN)...)
			continue
		}
		if pass.assumeRoleARN != "" {
			if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
				failed++
				log.Error("Startup validation failed: unable to assume role for inventory pass", err,
					passLogAttrs(pass.region, pass.assumeRoleARN)...)
				continue
			}
		} else if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
			// Ambient pass: WARN but do NOT fail. This restores the friendly "couldn't resolve
			// credentials" diagnostic the removed checkAWSCredentials used to give for the most common
			// misconfiguration, without reintroducing the exit-on-startup-blip behavior we avoid for the
			// ambient path — the pass still starts and retries each cycle.
			log.Warn("Could not resolve AWS credentials for the ambient inventory pass at startup; check the "+
				"task role, environment credentials, or ~/.aws/credentials. The agent will keep retrying each "+
				"cycle rather than exiting", passLogAttrs(cfg.Region, "")...)
		}
		// Store the region the SDK actually resolved (cfg.Region), not the configured value, which
		// may be empty when the region comes from AWS_REGION or instance metadata. This keeps every
		// downstream log/tracker line reporting the region the calls really targeted.
		ready = append(ready, readyPass{region: cfg.Region, assumeRoleARN: pass.assumeRoleARN, cfg: cfg})
	}
	if failed > 0 {
		return nil, fmt.Errorf(
			"startup validation failed: %d of %d inventory pass(es) could not be initialized; "+
				"fix the configuration/permissions and restart", failed, len(passes))
	}
	return ready, nil
}

// buildInventoryPasses turns the region + assume-role configuration into the set of gathers to run
// each polling cycle. With no roles configured this is a single pass against the agent's own
// account using region; with roles configured it is one pass per role (each with its own region).
func buildInventoryPasses(region string, assumeRoles []config.AssumeRoleConfig) []inventoryPass {
	if len(assumeRoles) == 0 {
		return []inventoryPass{{region: region}}
	}
	passes := make([]inventoryPass, 0, len(assumeRoles))
	for _, role := range assumeRoles {
		passes = append(passes, inventoryPass{
			region:        role.Region,
			assumeRoleARN: role.RoleARN,
			externalID:    role.ExternalID,
		})
	}
	return passes
}

// PeriodicallyGetInventoryReport periodically retrieves image results and reports/outputs them
// according to the configuration.
//
// Before entering the poll loop it runs startup validation (see preparePasses): every pass must have
// a resolvable region, and assume-role passes must be able to obtain credentials (performing the STS
// AssumeRole). If validation fails the function returns an error so the process can exit and the
// misconfiguration is surfaced immediately rather than silently under-reporting. Once the loop is
// running, per-cycle failures do NOT exit — they are logged and the next cycle retries — so a role
// (or a transient credential blip) that breaks after startup never crashloops the agent into
// monitoring nothing.
func PeriodicallyGetInventoryReport(
	pollingIntervalSeconds int,
	anchoreDetails connection.AnchoreInfo,
	region string,
	assumeRoles []config.AssumeRoleConfig,
	quiet, dryRun bool,
) error {
	ctx := context.Background()

	// The top-level region only applies to the ambient (no-role) pass; when assume-role entries are
	// configured each entry's own region is used. Warn rather than silently discard an explicitly
	// set region so an operator who set --region / ANCHORE_ECS_INVENTORY_REGION isn't left thinking
	// it took effect.
	if region != "" && len(assumeRoles) > 0 {
		log.Warn(
			"Top-level region (config/--region/ANCHORE_ECS_INVENTORY_REGION) is ignored because assume-role "+
				"entries are configured; each entry's own region is used instead",
			"ignoredRegion", region)
	}

	ready, err := preparePasses(ctx, inventory.BuildAWSConfig, buildInventoryPasses(region, assumeRoles))
	if err != nil {
		return err
	}
	log.Info("Startup validation passed", "passes", len(ready))

	// Fire off a ticker that reports according to a configurable polling interval
	ticker := time.NewTicker(time.Duration(pollingIntervalSeconds) * time.Second)

	for {
		cycleStart := time.Now()
		for _, pass := range ready {
			cfg := pass.cfg
			if pass.assumeRoleARN == "" {
				// Ambient credentials: rebuild the AWS config each cycle so a rotated static
				// credentials file is picked up without restarting the daemon. The region is pinned to
				// the value resolved at startup (stored on the pass), not re-read from AWS_REGION/IMDS
				// each cycle -- that keeps every per-pass log line honest about the region actually
				// queried. Assume-role passes instead reuse a cached config whose credentials cache
				// refreshes on its own; rotating the static *base* credentials feeding an assume-role
				// pass still requires a restart.
				rebuilt, err := inventory.BuildAWSConfig(ctx, pass.region, "", "")
				if err != nil {
					log.Error("Failed to load AWS config for region", err, "region", pass.region)
					continue
				}
				cfg = rebuilt
			}
			err := inventory.GetInventoryReportsForRegion(cfg, pass.assumeRoleARN, anchoreDetails, quiet, dryRun)
			if err != nil {
				// Runtime failures are logged and tolerated: the next cycle retries, and other
				// passes keep reporting. We deliberately do NOT exit here.
				log.Error("Failed to get Inventory Reports for region", err,
					passLogAttrs(pass.region, pass.assumeRoleARN)...)
			}
		}

		// The passes run serially, so a slow account (or many roles) can push a cycle past the polling
		// interval. When that happens the ticker below has already fired and the next cycle starts with
		// no delay, silently falling behind. Surface it so an operator can raise the interval or reduce
		// the number of passes instead of the drift going unnoticed.
		if elapsed := time.Since(cycleStart); cycleOverran(elapsed, pollingIntervalSeconds) {
			log.Warn("Inventory cycle took longer than the polling interval; reports may be stale and the next "+
				"cycle will start immediately. Consider increasing polling-interval-seconds or reducing the "+
				"number of assume-role entries",
				"cycleSeconds", elapsed.Seconds(), "pollingIntervalSeconds", pollingIntervalSeconds)
		}

		// Wait at least as long as the ticker
		log.Debugf("Start new gather %s", <-ticker.C)
	}
}

// cycleOverran reports whether a completed inventory cycle took longer than the configured polling
// interval, meaning the next tick fires immediately and reports are already going stale.
func cycleOverran(elapsed time.Duration, pollingIntervalSeconds int) bool {
	return elapsed > time.Duration(pollingIntervalSeconds)*time.Second
}

func SetLogger(logger logger.Logger) {
	log = logger
}
