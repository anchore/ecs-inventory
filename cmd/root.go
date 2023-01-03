package cmd

import (
	"fmt"
	"os"
	"runtime/pprof"

	"github.com/anchore/elastic-container-gatherer/ecg"
	"github.com/anchore/elastic-container-gatherer/ecg/mode"
	"github.com/anchore/elastic-container-gatherer/ecg/presenter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ecg",
	Short: "ECG tells Anchore which images are in use in your ECS clusters",
	Long:  "ECG (Elastic Container Gatherer) can poll Amazon ECS (Elastic Container Service) APIs to tell Anchore which Images are currently in-use",
	Args:  cobra.MaximumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		if appConfig.Dev.ProfileCPU {
			f, err := os.Create("cpu.profile")
			if err != nil {
				log.Error("unable to create CPU profile", err)
			} else {
				err := pprof.StartCPUProfile(f)
				if err != nil {
					log.Error("unable to start CPU profile", err)
				}
			}
		}

		if len(args) > 0 {
			err := cmd.Help()
			if err != nil {
				log.Error("error running help command", err)
				os.Exit(1)
			}
			os.Exit(1)
		}

		// TODO(bradjones) Validate anchore connection details here
		//if appConfig.AnchoreDetails.IsValid() {
		//dummyReport := inventory.Report{
		//Results: []inventory.ReportItem{},
		//}
		//err := reporter.Post(dummyReport, appConfig.AnchoreDetails, appConfig)
		//if err != nil {
		//log.Error("Failed to validate connection to Anchore", err)
		//}
		//} else {
		//log.Debug("Anchore details not specified, will not report inventory")
		//}

		switch appConfig.RunMode {
		case mode.PeriodicPolling:
			ecg.PeriodicallyGetInventoryReport(appConfig)
		default:
			report, err := ecg.GetInventoryReport(appConfig)
			if appConfig.Dev.ProfileCPU {
				pprof.StopCPUProfile()
			}
			if err != nil {
				log.Error("Failed to get Image Results", err)
				os.Exit(1)
			} else {
				err := ecg.HandleReport(report, appConfig)
				if err != nil {
					log.Error("Failed to handle Image Results", err)
					os.Exit(1)
				}
			}
		}
	},
}

func init() {
	// output & formatting options
	opt := "output"
	rootCmd.Flags().StringP(
		opt, "o", presenter.JSONPresenter.String(),
		fmt.Sprintf("report output formatter, options=%v", presenter.Options),
	)
	if err := viper.BindPFlag(opt, rootCmd.Flags().Lookup(opt)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", opt, err)
		os.Exit(1)
	}

	opt = "mode"
	rootCmd.Flags().StringP(opt, "m", mode.AdHoc.String(), fmt.Sprintf("execution mode, options=%v", mode.Modes))
	if err := viper.BindPFlag(opt, rootCmd.Flags().Lookup(opt)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", opt, err)
		os.Exit(1)
	}

	opt = "polling-interval-seconds"
	rootCmd.Flags().StringP(opt, "p", "300", "If mode is 'periodic', this specifies the interval")
	if err := viper.BindPFlag(opt, rootCmd.Flags().Lookup(opt)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", opt, err)
		os.Exit(1)
	}

	opt = "region"
	rootCmd.Flags().StringP(opt, "r", "", "If set overrides the AWS_REGION environment variable/region specified in ECG config")
	if err := viper.BindPFlag(opt, rootCmd.Flags().Lookup(opt)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", opt, err)
		os.Exit(1)
	}
}
