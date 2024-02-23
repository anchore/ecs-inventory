/*
The Config package handles the application configuration. Configurations can come from a variety of places, and
are listed below in order of precedence:
  - Command Line
  - .anchore-ecs-inventory.yaml
  - .anchore-ecs-inventory/config.yaml
  - ~/.anchore-ecs-inventory.yaml
  - <XDG_CONFIG_HOME>/anchore-ecs-inventory/config.yaml
  - Environment Variables prefixed with ANCHORE_ECS_INVENTORY_
*/package config

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/adrg/xdg"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/anchore/ecs-inventory/internal"
	"github.com/anchore/ecs-inventory/pkg/connection"
)

const redacted = "******"

// Configuration options that may only be specified on the command line
type CliOnlyOptions struct {
	ConfigPath string
	Verbosity  int
}

type AppConfig struct {
	Log                    Logging `mapstructure:"log"`
	CliOptions             CliOnlyOptions
	PollingIntervalSeconds int                    `mapstructure:"polling-interval-seconds"`
	AnchoreDetails         connection.AnchoreInfo `mapstructure:"anchore"`
	Region                 string                 `mapstructure:"region"`
	Quiet                  bool                   `mapstructure:"quiet"`   // if true do not log the inventory report to stdout
	DryRun                 bool                   `mapstructure:"dry-run"` // if true do not report inventory to Anchore
}

// Logging Configuration
type Logging struct {
	Level        string `mapstructure:"level"`
	FileLocation string `mapstructure:"file"`
}

var DefaultConfigValues = AppConfig{
	Log: Logging{
		Level:        "",
		FileLocation: "",
	},
	AnchoreDetails: connection.AnchoreInfo{
		Account: "admin",
		HTTP: connection.HTTPConfig{
			Insecure:       false,
			TimeoutSeconds: 60,
		},
	},
	Region:                 "",
	PollingIntervalSeconds: 300,
	Quiet:                  false,
	DryRun:                 false,
}

var ErrConfigFileNotFound = fmt.Errorf("application config file not found")

func setDefaultValues(v *viper.Viper) {
	v.SetDefault("log.level", DefaultConfigValues.Log.Level)
	v.SetDefault("log.file", DefaultConfigValues.Log.FileLocation)
	v.SetDefault("anchore.account", DefaultConfigValues.AnchoreDetails.Account)
	v.SetDefault("anchore.http.insecure", DefaultConfigValues.AnchoreDetails.HTTP.Insecure)
	v.SetDefault("anchore.http.timeout-seconds", DefaultConfigValues.AnchoreDetails.HTTP.TimeoutSeconds)
}

// Load the Application Configuration from the Viper specifications
func LoadConfigFromFile(v *viper.Viper, cliOpts *CliOnlyOptions) (*AppConfig, error) {
	// the user may not have a config, and this is OK, we can use the default config + default cobra cli values instead
	setDefaultValues(v)

	cliOptsConfigPath := ""
	if cliOpts != nil {
		cliOptsConfigPath = cliOpts.ConfigPath
	}

	err := readConfig(v, cliOptsConfigPath, internal.ApplicationName)
	if errors.Is(err, ErrConfigFileNotFound) {
		fmt.Println(
			"No config file found. One can be specified with the --config flag or " +
				"is present at one of the following locations:\n" +
				"\t- ./anchore-ecs-inventory.yaml\n" +
				"\t- ./.anchore-ecs-inventory/config.yaml\n" +
				"\t- $HOME/anchore-ecs-inventory.yaml\n" +
				"\t- $XDG_CONFIG_HOME/anchore-ecs-inventory/config.yaml\n\n" +
				"Using default configuration values.")
	} else if err != nil {
		return nil, err
	}

	config := &AppConfig{
		CliOptions: *cliOpts,
	}
	err = v.Unmarshal(config)
	if err != nil {
		return nil, fmt.Errorf("unable to parse config: %w", err)
	}

	err = config.Build()
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return config, nil
}

// Build the configuration object (to be used as a singleton)
func (cfg *AppConfig) Build() error {
	if cfg.Log.Level != "" {
		if cfg.CliOptions.Verbosity > 0 {
			return fmt.Errorf("cannot explicitly set log level (cfg file or env var) and use -v flag together")
		}
	} else {
		switch v := cfg.CliOptions.Verbosity; {
		case v == 1:
			cfg.Log.Level = "info"
		case v >= 2:
			cfg.Log.Level = "debug"
		default:
			cfg.Log.Level = "info"
		}
	}

	return nil
}

func readConfig(v *viper.Viper, configPath, applicationName string) error {
	v.AutomaticEnv()
	v.SetEnvPrefix(applicationName)
	// allow for nested options to be specified via environment variables
	// e.g. pod.context = APPNAME_POD_CONTEXT
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	if configPath != "" {
		fmt.Println("using config file:", configPath)
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err == nil {
			return nil
		}
		// don't fall through to other options if this fails
		return fmt.Errorf("unable to read config: %v", configPath)
	}

	// start searching for valid configs in order...

	// 1. look for .<appname>.yaml (in the current directory)
	v.AddConfigPath(".")
	v.SetConfigName(applicationName)
	if err := v.ReadInConfig(); err == nil {
		return nil
	}

	// 2. look for .<appname>/config.yaml (in the current directory)
	v.AddConfigPath("." + applicationName)
	v.SetConfigName("config")
	if err := v.ReadInConfig(); err == nil {
		return nil
	}

	// 3. look for ~/.<appname>.yaml
	home, err := homedir.Dir()
	if err == nil {
		v.AddConfigPath(home)
		v.SetConfigName("." + applicationName)
		if err := v.ReadInConfig(); err == nil {
			return nil
		}
	}

	// 4. look for <appname>/config.yaml in xdg locations (starting with xdg home config dir, then moving upwards)
	v.AddConfigPath(path.Join(xdg.ConfigHome, applicationName))
	for _, dir := range xdg.ConfigDirs {
		v.AddConfigPath(path.Join(dir, applicationName))
	}
	v.SetConfigName("config")
	if err := v.ReadInConfig(); err == nil {
		return nil
	}

	return ErrConfigFileNotFound
}

func (cfg AppConfig) String() string {
	// redact sensitive information
	// Note: If the configuration grows to have more redacted fields it would be good to refactor this into something that
	// is more dynamic based on a property or list of "sensitive" fields
	if cfg.AnchoreDetails.Password != "" {
		cfg.AnchoreDetails.Password = redacted
	}

	// yaml is pretty human friendly (at least when compared to json)
	appCfgStr, err := yaml.Marshal(&cfg)
	if err != nil {
		return err.Error()
	}

	return string(appCfgStr)
}
