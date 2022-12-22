package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/anchore/elastic-container-gatherer/ecg"
	"github.com/anchore/elastic-container-gatherer/internal/config"
	"github.com/anchore/elastic-container-gatherer/internal/logger"
)

var appConfig *config.AppConfig
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
	rootCmd.PersistentFlags().StringVarP(&cliOnlyOpts.ConfigPath, "config", "c", "", "application config file")
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

func GetAppConfig() *config.AppConfig {
	return appConfig
}

func initLogging() {
	logConfig := logger.LogConfig{
		Level:        appConfig.Log.Level,
		FileLocation: appConfig.Log.FileLocation,
	}

	logger.InitLogger(logConfig)
	log = logger.Log
	ecg.SetLogger(logger.Log)
}

func logAppConfig() {
	log.Debug("Application config", "config", appConfig)
}
