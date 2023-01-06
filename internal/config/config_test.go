package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestLoadConfigFromFileCliConfigPath(t *testing.T) {
	cliOpts := CliOnlyOptions{
		ConfigPath: "testdata/config.yaml",
	}
	cfg, err := LoadConfigFromFile(viper.GetViper(), &cliOpts)

	assert.Nil(t, err)
	assert.Equal(t, "info", cfg.Log.Level)
	assert.Equal(t, "/var/log/ecg.log", cfg.Log.FileLocation)
	assert.Equal(t, "http://localhost:8228", cfg.AnchoreDetails.URL)
	assert.Equal(t, "admin", cfg.AnchoreDetails.Account)
	assert.Equal(t, "admin", cfg.AnchoreDetails.User)
	assert.Equal(t, "foobar", cfg.AnchoreDetails.Password)
	assert.Equal(t, false, cfg.AnchoreDetails.HTTP.Insecure)
	assert.Equal(t, 10, cfg.AnchoreDetails.HTTP.TimeoutSeconds)
	assert.Equal(t, "us-east-1", cfg.Region)
	assert.Equal(t, 60, cfg.PollingIntervalSeconds)
}

func TestLoadConfigFromFileBadCliConfig(t *testing.T) {
	cliOpts := CliOnlyOptions{
		ConfigPath: "testdata/bad-config.yaml",
	}
	_, err := LoadConfigFromFile(viper.GetViper(), &cliOpts)

	assert.Error(t, err)
}

func TestReadConfigNoConfigsPresent(t *testing.T) {
	err := readConfig(viper.GetViper(), "", "ecg-but-not-really-lets-break-this-test")

	assert.Error(t, err)

}

func TestPasswordsAreObfuscated(t *testing.T) {
	// setup
	config := Application{
		ConfigPath:             "testdata/config.yaml",
		Log:                    Logging{},
		CliOptions:             CliOnlyOptions{},
		PollingIntervalSeconds: 300,
		AnchoreDetails: AnchoreInfo{
			URL:      "http://localhost:8228/v1",
			User:     "admin",
			Password: "foobar",
			Account:  "admin",
			HTTP:     HTTPConfig{},
		},
	}

	expected := `configpath: testdata/config.yaml
log:
  level: ""
  filelocation: ""
clioptions:
  configpath: ""
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
`

	// test
	assert.Equal(t, config.String(), expected)
}
