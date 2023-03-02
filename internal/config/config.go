/*
The Config package handles the application configuration. Configurations can come from a variety of places, and
are listed below in order of precedence:
  - Command Line
  - .ecg.yaml
  - .ecg/config.yaml
  - ~/.ecg.yaml
  - <XDG_CONFIG_HOME>/ecg/config.yaml
  - Environment Variables prefixed with ECG_
*/
package config

import (
	"fmt"
	"path"
	"strings"

	"github.com/adrg/xdg"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/anchore/elastic-container-gatherer/internal"
	"github.com/anchore/elastic-container-gatherer/ecg/connection"
)

const redacted = "******"

// Configuration options that may only be specified on the command line
type CliOnlyOptions struct {
	ConfigPath string
	Verbosity  int
}

type AppConfig struct {
	Log                    Logging				  `mapstructure:"log"`
	CliOptions             CliOnlyOptions
	PollingIntervalSeconds int					  `mapstructure:"polling-interval-seconds"`
	AnchoreDetails         connection.AnchoreInfo `mapstructure:"anchore"`
	Region                 string				  `mapstructure:"region"`
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
			TimeoutSeconds: 10,
		},
	},
	Region:                 "",
	PollingIntervalSeconds: 300,
}

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
	if err != nil {
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
			cfg.Log.Level = "error"
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

	return fmt.Errorf("application config not found")
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
