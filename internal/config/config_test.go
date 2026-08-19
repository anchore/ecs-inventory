package config

import (
	"fmt"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/ecs-inventory/pkg/connection"
	"github.com/anchore/ecs-inventory/pkg/inventory"
)

func TestBuildAssumeRoles(t *testing.T) {
	roles := func(n int) []inventory.AssumeRole {
		out := make([]inventory.AssumeRole, n)
		for i := range out {
			out[i] = inventory.AssumeRole{ARN: fmt.Sprintf("arn:aws:iam::00000000000%d:role/anchore", i)}
		}
		return out
	}

	tests := []struct {
		name      string
		cfg       AppConfig
		wantErr   string
		wantRoles []inventory.AssumeRole
	}{
		{
			name:      "no roles configured",
			cfg:       AppConfig{},
			wantRoles: nil,
		},
		{
			name: "single role flag folds into the list",
			cfg:  AppConfig{AssumeRoleARN: "arn:aws:iam::111111111111:role/anchore", ExternalID: "ext-1"},
			wantRoles: []inventory.AssumeRole{
				{ARN: "arn:aws:iam::111111111111:role/anchore", ExternalID: "ext-1"},
			},
		},
		{
			name: "single role flag appends to a configured list",
			cfg: AppConfig{
				AssumeRoles:   []inventory.AssumeRole{{ARN: "arn:aws:iam::111111111111:role/anchore"}},
				AssumeRoleARN: "arn:aws:iam::222222222222:role/anchore",
			},
			wantRoles: []inventory.AssumeRole{
				{ARN: "arn:aws:iam::111111111111:role/anchore"},
				{ARN: "arn:aws:iam::222222222222:role/anchore"},
			},
		},
		{
			name:      "at the cap is allowed",
			cfg:       AppConfig{AssumeRoles: roles(inventory.MaxAssumeRoles)},
			wantRoles: roles(inventory.MaxAssumeRoles),
		},
		{
			name:    "over the cap is rejected",
			cfg:     AppConfig{AssumeRoles: roles(inventory.MaxAssumeRoles + 1)},
			wantErr: "at most 5 are supported",
		},
		{
			// the flag pushing a full list over the cap must be caught too
			name: "at the cap plus the single role flag is rejected",
			cfg: AppConfig{
				AssumeRoles:   roles(inventory.MaxAssumeRoles),
				AssumeRoleARN: "arn:aws:iam::999999999999:role/anchore",
			},
			wantErr: "at most 5 are supported",
		},
		{
			name:    "role without an arn is rejected",
			cfg:     AppConfig{AssumeRoles: []inventory.AssumeRole{{ExternalID: "ext-1"}}},
			wantErr: "assume-roles[0] has no arn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			err := cfg.buildAssumeRoles()

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantRoles, cfg.AssumeRoles)
		})
	}
}

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
		Region: "us-east-1",
		AssumeRoles: []inventory.AssumeRole{
			{ARN: "arn:aws:iam::111111111111:role/anchore-ecs-inventory", ExternalID: "test-external-id"},
			{ARN: "arn:aws:iam::222222222222:role/anchore-ecs-inventory"},
		},
		PollingIntervalSeconds: 60,
		Quiet:                  true,
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
assumeroles: []
assumerolearn: ""
externalid: ""
quiet: false
dryrun: false
`

	assert.Equal(t, expected, config.String())
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
	}

	assert.EqualValues(t, expectedCfg, appCfg)
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
