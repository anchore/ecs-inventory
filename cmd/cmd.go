package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/anchore/ecs-inventory/internal/config"
	"github.com/anchore/ecs-inventory/internal/logger"
	"github.com/anchore/ecs-inventory/pkg"
	pkgLog "github.com/anchore/ecs-inventory/pkg/logger"
)

var (
	appConfig   *config.AppConfig
	cliOnlyOpts config.CliOnlyOptions
	log         pkgLog.Logger
)

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
		fmt.Printf("Failed to load application config: \n\t%+v\n", err)
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

	logger.Log = logger.InitZapLogger(logConfig)
	log = logger.Log
	pkg.SetLogger(logger.Log)
}

func logAppConfig() {
	log.Debug("Application config", "config", appConfig)
}
