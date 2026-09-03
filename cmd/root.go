package cmd

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/anchore/ecs-inventory/internal/config"
	"github.com/anchore/ecs-inventory/pkg"
	"github.com/anchore/ecs-inventory/pkg/reporter"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "anchore-ecs-inventory",
	Short: "anchore-ecs-inventory tells Anchore which images are in use in your ECS clusters",
	Long:  "anchore-ecs-inventory can poll Amazon ECS (Elastic Container Service) APIs to tell Anchore which Images are currently in-use",
	Args:  cobra.MaximumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			err := cmd.Help()
			if err != nil {
				log.Error("error running help command", err)
				os.Exit(1)
			}
			os.Exit(1)
		}
		log.Info("Starting anchore-ecs-inventory")

		// Region validation happens per-pass at startup inside PeriodicallyGetInventoryReport: a pass
		// with no resolvable region (config, --region, env, or instance metadata) fails fast there
		// rather than silently reporting nothing every cycle.

		// Validate anchore connection & credentials, using a dummy report to post but this will be
		// replaced in the future with a health check endpoint for the agents
		if appConfig.AnchoreDetails.IsValid() {
			dummyReport := reporter.Report{
				ClusterARN: "validating-creds",
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
			}
			err := reporter.Post(dummyReport, appConfig.AnchoreDetails)
			if err != nil {
				log.Error("Failed to validate connection to Anchore", err)
			} else {
				log.Info("Successfully validated connection to Anchore")
			}
		} else {
			log.Warn("Anchore details not specified, will not report inventory")
		}

		// PeriodicallyGetInventoryReport only returns if startup validation fails; a healthy agent
		// blocks here forever. Exit non-zero on startup-validation failure so ECS surfaces the
		// misconfiguration (e.g. via task restarts/alarms) instead of running blind.
		if err := pkg.PeriodicallyGetInventoryReport(
			appConfig.PollingIntervalSeconds,
			appConfig.AnchoreDetails,
			appConfig.Region,
			appConfig.AssumeRole,
			appConfig.Quiet,
			appConfig.DryRun,
		); err != nil {
			log.Error("Shutting down: startup validation failed", err)
			os.Exit(1)
		}
	},
}

func init() {
	opt := "polling-interval-seconds"
	rootCmd.Flags().
		StringP(opt, "p", strconv.Itoa(config.DefaultConfigValues.PollingIntervalSeconds), "this specifies the polling interval of the ECS API in seconds")
	if err := viper.BindPFlag(opt, rootCmd.Flags().Lookup(opt)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", opt, err)
		os.Exit(1)
	}

	opt = "region"
	rootCmd.Flags().
		StringP(opt, "r", config.DefaultConfigValues.Region, "AWS region to inventory using the agent's own credentials (overrides AWS_REGION and the config file's region); ignored when assume-role entries are configured, which use each entry's own region")
	if err := viper.BindPFlag(opt, rootCmd.Flags().Lookup(opt)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", opt, err)
		os.Exit(1)
	}

	opt = "quiet"
	rootCmd.Flags().
		BoolP(opt, "q", config.DefaultConfigValues.Quiet, "suppresses inventory report output to stdout")
	if err := viper.BindPFlag(opt, rootCmd.Flags().Lookup(opt)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", opt, err)
		os.Exit(1)
	}

	opt = "dry-run"
	rootCmd.Flags().
		BoolP(opt, "d", config.DefaultConfigValues.DryRun, "do not report inventory to Anchore")
	if err := viper.BindPFlag(opt, rootCmd.Flags().Lookup(opt)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", opt, err)
		os.Exit(1)
	}
}
