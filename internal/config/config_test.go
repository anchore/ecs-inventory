package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/ecs-inventory/pkg/connection"
)

// loadConfigFromContent writes content to a temp config.yaml and runs it through the full load
// pipeline (read -> unmarshal -> Build), returning the result.
func loadConfigFromContent(t *testing.T, content []byte) (*AppConfig, error) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(f, content, 0o644))
	return LoadConfigFromFile(viper.GetViper(), &CliOnlyOptions{ConfigPath: f})
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
		Region:                 "us-east-1",
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

// TestLoadConfigFromFileReturnsErrorWhenConfigNotReadable documents the CURRENT behavior for an
// explicitly-configured config file the process cannot read (e.g. no read permission): unlike the
// log-file case (which panics), config loading returns a clear "unable to read config" error that
// cmd.InitAppConfig turns into a message + os.Exit(1). Characterization test; behavior unchanged.
func TestLoadConfigFromFileReturnsErrorWhenConfigNotReadable(t *testing.T) {
	t.Cleanup(cleanup)
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses file permissions")
	}

	f := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(f, []byte("region: us-east-1\n"), 0o000)) // exists but not readable

	_, err := LoadConfigFromFile(viper.GetViper(), &CliOnlyOptions{ConfigPath: f})

	assert.Error(t, err)
	// The underlying reason is preserved, so a permission failure is distinguishable from a parse
	// failure (rather than every mode collapsing to the same opaque "unable to read config" string).
	assert.ErrorContains(t, err, "unable to read config")
	assert.ErrorContains(t, err, "permission denied")
}

func TestLoadConfigRejectsBinaryFile(t *testing.T) {
	t.Cleanup(cleanup)

	// A binary blob supplied as the config file must fail cleanly (YAML parse error), not crash.
	bin := make([]byte, 512)
	for i := range bin {
		bin[i] = byte(i)
	}

	_, err := loadConfigFromContent(t, bin)

	assert.Error(t, err)
	// A parse failure surfaces the YAML reason, distinct from the permission-denied case above.
	assert.ErrorContains(t, err, "yaml:")
	assert.NotErrorIs(t, err, os.ErrPermission)
}

func TestLoadConfigRejectsOversizedAssumeRoleListFromFile(t *testing.T) {
	t.Cleanup(cleanup)

	// A large assume-role list parsed from a file is bounded by the cap and rejected -- exercises the
	// full file -> parse -> Build path (not just the in-memory struct validation).
	var sb strings.Builder
	sb.WriteString("assume-role:\n")
	for i := 0; i < MaxAssumeRoleEntries+5; i++ {
		sb.WriteString("  - role-arn: arn:aws:iam::111111111111:role/a\n    region: us-east-1\n")
	}

	_, err := loadConfigFromContent(t, []byte(sb.String()))

	assert.ErrorContains(t, err, "too many assume-role entries")
}

func TestLoadConfigRejectsYAMLAliasBomb(t *testing.T) {
	t.Cleanup(cleanup)

	// A "billion laughs" alias bomb must be rejected by the YAML parser, not expanded (which would
	// blow up memory/CPU from a tiny file). go-yaml caps alias expansion; assert a clean error and,
	// implicitly, that the load returns promptly rather than hanging.
	bomb := []byte(`
a: &a ["x","x","x","x","x","x","x","x","x"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
`)

	_, err := loadConfigFromContent(t, bomb)

	assert.Error(t, err)
	// go-yaml surfaces the specific reason; assert it so this stays a parse-time rejection, not an
	// accidental hang/expansion, and remains distinct from the permission-denied case.
	assert.ErrorContains(t, err, "excessive aliasing")
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
assumerole: []
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

func TestRegionResolvesFromEnvVar(t *testing.T) {
	t.Cleanup(cleanup)

	// AutomaticEnv maps ANCHORE_ECS_INVENTORY_REGION onto the top-level `region` key and overrides the
	// config file, so an operator can set the ambient region from the environment. This guards the
	// region-resolution precedence (env wins; the file value is only a fallback) -- the source of an
	// earlier surprise where an unset env var left the file's literal placeholder as the region.
	t.Setenv("ANCHORE_ECS_INVENTORY_REGION", "ap-southeast-2")
	cliOpts := CliOnlyOptions{
		ConfigPath: "testdata/config.yaml", // file sets region: "us-east-1"
	}

	appCfg, err := LoadConfigFromFile(viper.GetViper(), &cliOpts)

	assert.NoError(t, err)
	assert.Equal(t, "ap-southeast-2", appCfg.Region, "ANCHORE_ECS_INVENTORY_REGION should override the config file")
}

func TestAssumeRoleListParsedFromFile(t *testing.T) {
	t.Cleanup(cleanup)

	cliOpts := CliOnlyOptions{
		ConfigPath: "testdata/assume-role-config.yaml",
	}
	appCfg, err := LoadConfigFromFile(viper.GetViper(), &cliOpts)

	assert.NoError(t, err)
	assert.Equal(t, []AssumeRoleConfig{
		{RoleARN: "arn:aws:iam::111111111111:role/a", ExternalID: "ext-a", Region: "us-west-2"},
		{RoleARN: "arn:aws:iam::222222222222:role/b", Region: "eu-west-1"},
	}, appCfg.AssumeRole)
}

func TestAssumeRoleEntryRequiresRoleARN(t *testing.T) {
	t.Cleanup(cleanup)

	cfg := AppConfig{
		AssumeRole: []AssumeRoleConfig{
			{Region: "us-west-2"}, // missing role-arn
		},
	}

	err := cfg.Build()
	assert.ErrorContains(t, err, "assume-role entry 0 is missing a required role-arn")
}

func TestAssumeRoleLimitEnforced(t *testing.T) {
	t.Cleanup(cleanup)

	roles := make([]AssumeRoleConfig, MaxAssumeRoleEntries+1)
	for i := range roles {
		roles[i] = AssumeRoleConfig{RoleARN: "arn:aws:iam::111111111111:role/a"}
	}
	cfg := AppConfig{AssumeRole: roles}

	err := cfg.Build()
	assert.ErrorContains(t, err, "too many assume-role entries")
	// Assert the actual limit VALUE, not just that some limit fired. The other limit tests key off
	// the MaxAssumeRoleEntries constant, so they would pass even if it drifted; this pins the intended
	// cap of 20 so an accidental change (e.g. back to 50) is caught here.
	assert.ErrorContains(t, err, "maximum is 20")
}

func TestMaxAssumeRoleEntriesIsTwenty(t *testing.T) {
	// The intended cap is 20. If this changes, it should be a deliberate product decision, not a drift.
	assert.Equal(t, 20, MaxAssumeRoleEntries)
}

func TestAssumeRoleRejectsControlCharacters(t *testing.T) {
	t.Cleanup(cleanup)

	// Control characters (CR, LF, tab, ...) are never valid in these fields. Rejecting them at config
	// validation turns what would otherwise be a murky STS/endpoint error at startup pre-flight into a
	// clear per-entry message.
	base := AssumeRoleConfig{RoleARN: "arn:aws:iam::111111111111:role/a", Region: "us-east-1", ExternalID: "ext-id"}

	tests := []struct {
		name        string
		mutate      func(*AssumeRoleConfig)
		errContains string // "" means the entry is valid and Build must not error
	}{
		{"clean entry is accepted", func(r *AssumeRoleConfig) {}, ""},
		{"line feed in role-arn", func(r *AssumeRoleConfig) { r.RoleARN += "\n" }, "assume-role entry 0: role-arn contains invalid control characters"},
		{"carriage return in role-arn", func(r *AssumeRoleConfig) { r.RoleARN += "\r" }, "role-arn contains invalid control characters"},
		{"CRLF in region", func(r *AssumeRoleConfig) { r.Region += "\r\n" }, "region contains invalid control characters"},
		{"tab in external-id", func(r *AssumeRoleConfig) { r.ExternalID = "ext\tid" }, "external-id contains invalid control characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := base
			tt.mutate(&role)
			cfg := AppConfig{AssumeRole: []AssumeRoleConfig{role}}

			err := cfg.Build()

			if tt.errContains == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestAssumeRoleAtLimitAllowed(t *testing.T) {
	t.Cleanup(cleanup)

	roles := make([]AssumeRoleConfig, MaxAssumeRoleEntries)
	for i := range roles {
		roles[i] = AssumeRoleConfig{RoleARN: "arn:aws:iam::111111111111:role/a", Region: "us-east-1"}
	}
	cfg := AppConfig{AssumeRole: roles}

	err := cfg.Build()
	assert.NoError(t, err)
}

func TestAssumeRoleEntryRequiresRegion(t *testing.T) {
	t.Cleanup(cleanup)

	cfg := AppConfig{
		AssumeRole: []AssumeRoleConfig{
			{RoleARN: "arn:aws:iam::111111111111:role/a"}, // missing region
		},
	}

	err := cfg.Build()
	assert.ErrorContains(t, err, "assume-role entry 0 (arn:aws:iam::111111111111:role/a) is missing a required region")
}

func TestAssumeRoleRejectedViaEnvVar(t *testing.T) {
	t.Cleanup(cleanup)

	// Setting the assume-role list via env var is unsupported and must fail with a clear message
	// rather than the cryptic viper/mapstructure error it would otherwise produce.
	t.Setenv(assumeRoleEnvVar, "arn:aws:iam::111111111111:role/a")

	cliOpts := CliOnlyOptions{
		ConfigPath: "testdata/config.yaml",
	}
	_, err := LoadConfigFromFile(viper.GetViper(), &cliOpts)

	assert.ErrorContains(t, err, "assume-role cannot be set via environment variables")
	assert.ErrorContains(t, err, assumeRoleEnvVar)
}

func TestAssumeRoleEnvVarNameMatchesViperConvention(t *testing.T) {
	// Guard against the env-var name drifting away from the ANCHORE_ECS_INVENTORY_ prefix + key
	// replacer convention viper uses, which is what makes the detection in LoadConfigFromFile work.
	assert.Equal(t, "ANCHORE_ECS_INVENTORY_ASSUME_ROLE", assumeRoleEnvVar)
}

func cleanup() {
	viper.Reset()
}
