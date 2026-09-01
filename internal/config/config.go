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
	"os"
	"path"
	"strings"
	"unicode"

	"github.com/adrg/xdg"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/anchore/ecs-inventory/internal"
	"github.com/anchore/ecs-inventory/pkg/connection"
)

const redacted = "******"

// MaxAssumeRoleEntries is a compiled-in upper bound on the number of assume-role entries a single
// agent will accept. Each entry produces an independent inventory pass every polling cycle, so this
// caps the per-cycle fan-out (and the STS/ECS call volume it implies) at a value we've validated.
const MaxAssumeRoleEntries = 20

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
	// Region is the AWS region to inventory using the agent's ambient credentials. It is used only
	// when no AssumeRole entries are configured; when assuming roles the region comes from each
	// AssumeRole entry instead. May be empty, in which case the AWS SDK resolves the region normally
	// (e.g. from AWS_REGION or instance metadata).
	Region string `mapstructure:"region"`
	// AssumeRole is a list of roles to assume (via STS), each producing an independent inventory pass.
	// Zero entries means inventory the agent's own account/Region directly. One or more entries lets a
	// single agent cover multiple account-regions. Each role may live in the same or a different AWS
	// account, provided its trust policy permits the agent's base credentials to assume it.
	AssumeRole []AssumeRoleConfig `mapstructure:"assume-role"`
	Quiet      bool               `mapstructure:"quiet"`   // if true do not log the inventory report to stdout
	DryRun     bool               `mapstructure:"dry-run"` // if true do not report inventory to Anchore
}

// AssumeRoleConfig describes a single IAM role to assume and the region to inventory using the
// resulting credentials.
type AssumeRoleConfig struct {
	// RoleARN is the ARN of the IAM role to assume. Required for each entry.
	RoleARN string `mapstructure:"role-arn"`
	// Region is the AWS region to inventory using the assumed credentials. Required for each entry:
	// the top-level region does not apply to assume-role entries, so without an explicit region a
	// pass would silently fall back to the agent's home-region resolution and inventory the wrong
	// region.
	Region string `mapstructure:"region"`
	// ExternalID, if set, is passed when assuming the role. Some roles (commonly cross-account,
	// third-party roles) require an external ID in their trust policy. Optional.
	ExternalID string `mapstructure:"external-id"`
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
	AssumeRole:             nil,
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

	// The assume-role list cannot be populated from the environment; fail early with a clear message
	// rather than letting viper produce a cryptic mapstructure error later.
	if err := assertAssumeRoleNotSetViaEnv(); err != nil {
		return nil, err
	}

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

	// Cap the number of roles to the compiled-in limit to bound per-cycle fan-out.
	if len(cfg.AssumeRole) > MaxAssumeRoleEntries {
		return fmt.Errorf("too many assume-role entries: %d configured, maximum is %d", len(cfg.AssumeRole), MaxAssumeRoleEntries)
	}

	// Each assume-role entry must specify a role ARN and a region. The top-level region is not used
	// for assume-role passes, so an entry without its own region would silently inventory the wrong
	// place; require it explicitly rather than falling back.
	for i, role := range cfg.AssumeRole {
		if role.RoleARN == "" {
			return fmt.Errorf("assume-role entry %d is missing a required role-arn", i)
		}
		if role.Region == "" {
			return fmt.Errorf("assume-role entry %d (%s) is missing a required region", i, role.RoleARN)
		}
		// Reject control characters (CR, LF, tab, NUL, ...) in each field. They are never valid in an
		// ARN, region, or external ID and usually mean a copy/paste or templating slip in the config;
		// caught here they produce a clear per-entry error instead of a murky STS/endpoint failure at
		// startup pre-flight. The role-arn is checked first, so it is control-char-free by the time it
		// appears in the region/external-id messages.
		if containsControlChar(role.RoleARN) {
			return fmt.Errorf("assume-role entry %d: role-arn contains invalid control characters", i)
		}
		if containsControlChar(role.Region) {
			return fmt.Errorf("assume-role entry %d (%s): region contains invalid control characters", i, role.RoleARN)
		}
		if containsControlChar(role.ExternalID) {
			return fmt.Errorf("assume-role entry %d (%s): external-id contains invalid control characters", i, role.RoleARN)
		}
	}

	return nil
}

// containsControlChar reports whether s contains any Unicode control character (e.g. CR, LF, tab,
// NUL). Such characters are never legitimate in the assume-role fields.
func containsControlChar(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

// assumeRoleEnvVar is the environment variable name that viper's AutomaticEnv would map the
// assume-role key to. The assume-role list is config-file-only; if an operator sets this env var,
// viper shadows the file's list with a scalar string and mapstructure fails with a cryptic
// "expected a map or struct, got string" error. We detect it and fail with a clear message instead.
var assumeRoleEnvVar = strings.ToUpper(strings.NewReplacer("-", "_").Replace(internal.ApplicationName + "_assume-role"))

// assertAssumeRoleNotSetViaEnv returns a clear error if the assume-role list was set via an
// environment variable, which is unsupported (see assumeRoleEnvVar).
func assertAssumeRoleNotSetViaEnv() error {
	if _, ok := os.LookupEnv(assumeRoleEnvVar); ok {
		return fmt.Errorf(
			"assume-role cannot be set via environment variables (%s); configure the assume-role list in a config file instead",
			assumeRoleEnvVar,
		)
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
		// Don't fall through to the other locations if an explicitly-configured path fails, and surface
		// the underlying reason (YAML parse error with line/column, permission denied, etc.) rather than
		// a generic message the operator can't act on.
		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("unable to read config %q: %w", configPath, err)
		}
		return nil
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
