package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/anchore/anchore-ecs-inventory/internal/config"
	"github.com/anchore/anchore-ecs-inventory/internal/logger"
	"github.com/anchore/anchore-ecs-inventory/pkg"
)

var (
	appConfig   *config.AppConfig
	cliOnlyOpts config.CliOnlyOptions
	log         logger.Logger
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
	if errors.Is(err, config.ErrConfigNotFound) {
		fmt.Println(
			"Please ensure that a config file is specified with the --config flag or " +
				"is present at one of the following locations:\n" +
				"\t- ./anchore-ecs-inventory.yaml\n" +
				"\t- ./.anchore-ecs-inventory/config.yaml\n" +
				"\t- $HOME/anchore-ecs-inventory.yaml\n" +
				"\t- $XDG_CONFIG_HOME/anchore-ecs-inventory/config.yaml")
		os.Exit(1)
	} else if err != nil {
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

	logger.InitLogger(logConfig)
	log = logger.Log
	pkg.SetLogger(logger.Log)
}

func logAppConfig() {
	log.Debug("Application config", "config", appConfig)
}
