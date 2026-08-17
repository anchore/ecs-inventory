package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/ecs-inventory/pkg/connection"
)

func TestLoadConfigFromFileCliConfigPath(t *testing.T) {
	t.Cleanup(cleanup)

	cliOpts := CliOnlyOptions{
		ConfigPath: "testdata/config.yaml",
	}
	appCfg, err := LoadConfigFromFile(viper.GetViper(), &cliOpts)

	assert.NoError(t, err)

	expectedCfg := &AppConfig{
		CliOptions: CliOnlyOptions{
			ConfigPath: "testdata/config.yaml",
		},
		Log: Logging{
			Level:        "info",
			FileLocation: "/var/log/anchore-ecs-inventory.log",
		},
		AnchoreDetails: connection.AnchoreInfo{
			Account:  "admin",
			User:     "admin",
			Password: "foobar",
			URL:      "http://localhost:8228",
			HTTP: connection.HTTPConfig{
				Insecure:       false,
				TimeoutSeconds: 10,
			},
		},
		Region:                 "us-east-1",
		PollingIntervalSeconds: 60,
		Quiet:                  true,
		Registration: RegistrationOptions{
			RegistrationID:         "test-registration-id",
			RegistrationInstanceID: "test-registration-instance-id",
			IntegrationName:        "test-integration-name",
			IntegrationDescription: "test integration description",
		},
		HealthReportIntervalSeconds: 120,
	}

	assert.EqualValues(t, expectedCfg, appCfg)
}

func TestLoadConfigFromFileBadCliConfig(t *testing.T) {
	t.Cleanup(cleanup)

	cliOpts := CliOnlyOptions{
		ConfigPath: "testdata/bad-config.yaml",
	}
	_, err := LoadConfigFromFile(viper.GetViper(), &cliOpts)

	assert.Error(t, err)
}

func TestReadConfigNoConfigsPresent(t *testing.T) {
	t.Cleanup(cleanup)

	err := readConfig(viper.GetViper(), "", "anchore-ecs-inventory-but-not-really-lets-break-this-test")

	assert.Error(t, err)
}

func TestPasswordsAreObfuscated(t *testing.T) {
	t.Cleanup(cleanup)

	config := AppConfig{
		Log: Logging{},
		CliOptions: CliOnlyOptions{
			ConfigPath: "testdata/config.yaml",
		},
		PollingIntervalSeconds: 300,
		AnchoreDetails: connection.AnchoreInfo{
			URL:      "http://localhost:8228/v1",
			User:     "admin",
			Password: "foobar",
			Account:  "admin",
			HTTP:     connection.HTTPConfig{},
		},
		HealthReportIntervalSeconds: 60,
	}

	expected := `log:
  level: ""
  filelocation: ""
clioptions:
  configpath: testdata/config.yaml
  verbosity: 0
pollingintervalseconds: 300
anchoredetails:
  url: http://localhost:8228/v1
  user: admin
  password: '******'
  account: admin
  http:
    insecure: false
    timeoutseconds: 0
region: ""
quiet: false
dryrun: false
registration:
  registrationid: ""
  registrationinstanceid: ""
  integrationname: ""
  integrationdescription: ""
healthreportintervalseconds: 60
`

	assert.Equal(t, expected, config.String())
}

func TestHealthReportIntervalIsValidated(t *testing.T) {
	tests := []struct {
		name    string
		seconds int
		wantErr bool
	}{
		{name: "below lower bound", seconds: 29, wantErr: true},
		{name: "lower bound", seconds: 30, wantErr: false},
		{name: "default", seconds: 60, wantErr: false},
		{name: "upper bound", seconds: 600, wantErr: false},
		{name: "above upper bound", seconds: 601, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := AppConfig{HealthReportIntervalSeconds: tt.seconds}

			err := cfg.Build()

			if tt.wantErr {
				assert.ErrorContains(t, err, "health-report-interval-seconds must be between 30 and 600")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDefaultValuesSuppliedForEmptyConfig(t *testing.T) {
	t.Cleanup(cleanup)

	configPath := "testdata/empty_config.yaml"

	cliOpts := CliOnlyOptions{
		ConfigPath: configPath,
	}

	appCfg, err := LoadConfigFromFile(viper.GetViper(), &cliOpts)
	assert.NoError(t, err)

	expectedCfg := &AppConfig{
		CliOptions: CliOnlyOptions{
			ConfigPath: configPath,
		},
		Log: Logging{
			Level: "info",
		},
		AnchoreDetails: connection.AnchoreInfo{
			Account:  "admin",
			Password: "",
			HTTP: connection.HTTPConfig{
				Insecure:       false,
				TimeoutSeconds: 60,
			},
		},
		HealthReportIntervalSeconds: 60,
	}

	assert.EqualValues(t, expectedCfg, appCfg)
}

// viper's AutomaticEnv only resolves keys it already knows about, so every option has
// to be registered as a default for the documented ANCHORE_ECS_INVENTORY_ overrides to
// reach it.
func TestRegistrationOptionsCanBeSetByEnvironment(t *testing.T) {
	t.Cleanup(cleanup)

	t.Setenv("ANCHORE_ECS_INVENTORY_ANCHORE_REGISTRATION_REGISTRATION_ID", "id-from-env")
	t.Setenv("ANCHORE_ECS_INVENTORY_ANCHORE_REGISTRATION_REGISTRATION_INSTANCE_ID", "instance-id-from-env")
	t.Setenv("ANCHORE_ECS_INVENTORY_ANCHORE_REGISTRATION_INTEGRATION_NAME", "name-from-env")
	t.Setenv("ANCHORE_ECS_INVENTORY_ANCHORE_REGISTRATION_INTEGRATION_DESCRIPTION", "description-from-env")
	t.Setenv("ANCHORE_ECS_INVENTORY_HEALTH_REPORT_INTERVAL_SECONDS", "45")

	cliOpts := CliOnlyOptions{ConfigPath: "testdata/empty_config.yaml"}
	appCfg, err := LoadConfigFromFile(viper.GetViper(), &cliOpts)
	assert.NoError(t, err)

	assert.Equal(t, RegistrationOptions{
		RegistrationID:         "id-from-env",
		RegistrationInstanceID: "instance-id-from-env",
		IntegrationName:        "name-from-env",
		IntegrationDescription: "description-from-env",
	}, appCfg.Registration)
	assert.Equal(t, 45, appCfg.HealthReportIntervalSeconds)
}

func TestCliOptsOverrideConfigFileOpts(t *testing.T) {
	t.Cleanup(cleanup)

	expectedRegion := "eu-west-2"
	cliOpts := CliOnlyOptions{
		ConfigPath: "testdata/config.yaml",
	}

	viper.Set("Region", expectedRegion)

	// Config file is set to "us-east-1"
	appCfg, err := LoadConfigFromFile(viper.GetViper(), &cliOpts)

	assert.NoError(t, err)
	assert.Equal(t, expectedRegion, appCfg.Region)
}

func cleanup() {
	viper.Reset()
}
