package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/elastic-container-gatherer/ecg"
	"github.com/anchore/elastic-container-gatherer/internal/config"
	"github.com/anchore/elastic-container-gatherer/internal/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var appConfig *config.Application
var cliOnlyOpts config.CliOnlyOptions
var log logger.Logger

func init() {
	setGlobalCliOptions()

	cobra.OnInitialize(
		InitAppConfig,
		initLogging,
		logAppConfig,
	)
}

func setGlobalCliOptions() {
	// setup global CLI options (available on all CLI commands)
	rootCmd.PersistentFlags().StringVarP(&cliOnlyOpts.ConfigPath, "config", "c", "", "application config file")

	flag := "quiet"
	rootCmd.PersistentFlags().BoolP(
		flag, "q", false,
		"suppress all logging output",
	)
	if err := viper.BindPFlag(flag, rootCmd.PersistentFlags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	rootCmd.PersistentFlags().CountVarP(&cliOnlyOpts.Verbosity, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func InitAppConfig() {
	cfg, err := config.LoadConfigFromFile(viper.GetViper(), &cliOnlyOpts)
	if err != nil {
		fmt.Printf("failed to load application config: \n\t%+v\n", err)
		os.Exit(1)
	}
	appConfig = cfg
}

func GetAppConfig() *config.Application {
	return appConfig
}

func initLogging() {
	logConfig := logger.LogConfig{
		Level:        appConfig.Log.Level,
		FileLocation: appConfig.Log.FileLocation,
		Dev:          appConfig.Dev.Log,
	}

	logger.InitLogger(logConfig)
	log = logger.Log
	ecg.SetLogger(logger.Log)
}

func logAppConfig() {
	log.Debug("Application config", appConfig)
}
