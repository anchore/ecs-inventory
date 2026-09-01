package pkg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/ecs-inventory/internal/config"
	"github.com/anchore/ecs-inventory/pkg/logger"
)

type mockLogger struct{}

func (m *mockLogger) Error(msg string, err error, args ...interface{}) {}
func (m *mockLogger) Warn(msg string, args ...interface{})             {}
func (m *mockLogger) Warnf(msg string, args ...interface{})            {}
func (m *mockLogger) Info(msg string, args ...interface{})             {}
func (m *mockLogger) Debug(msg string, args ...interface{})            {}
func (m *mockLogger) Debugf(msg string, args ...interface{})           {}

// recordingLogger captures the messages passed to Warn/Info so tests can assert on what the agent
// actually logged (not just that it didn't crash).
type recordingLogger struct {
	warns []string
	infos []string
}

func (r *recordingLogger) Error(msg string, err error, args ...interface{}) {}
func (r *recordingLogger) Warn(msg string, args ...interface{})             { r.warns = append(r.warns, msg) }
func (r *recordingLogger) Warnf(msg string, args ...interface{})            {}
func (r *recordingLogger) Info(msg string, args ...interface{})             { r.infos = append(r.infos, msg) }
func (r *recordingLogger) Debug(msg string, args ...interface{})            {}
func (r *recordingLogger) Debugf(msg string, args ...interface{})           {}

func containsSubstr(msgs []string, substr string) bool {
	for _, m := range msgs {
		if strings.Contains(m, substr) {
			return true
		}
	}
	return false
}

func TestSetLogger(t *testing.T) {
	mock := &mockLogger{}
	SetLogger(mock)
	assert.Equal(t, logger.Logger(mock), log)
}

func TestBuildInventoryPasses(t *testing.T) {
	tests := []struct {
		name        string
		region      string
		assumeRoles []config.AssumeRoleConfig
		want        []inventoryPass
	}{
		{
			name:   "no roles uses top-level region",
			region: "us-east-1",
			want:   []inventoryPass{{region: "us-east-1"}},
		},
		{
			name:   "no roles and empty region still yields a single pass",
			region: "",
			want:   []inventoryPass{{region: ""}},
		},
		{
			name:   "single role uses its own region and ignores top-level region",
			region: "us-east-1",
			assumeRoles: []config.AssumeRoleConfig{
				{RoleARN: "arn:aws:iam::123456789012:role/foo", ExternalID: "ext", Region: "us-west-2"},
			},
			want: []inventoryPass{
				{region: "us-west-2", assumeRoleARN: "arn:aws:iam::123456789012:role/foo", externalID: "ext"},
			},
		},
		{
			name:   "multiple roles produce one pass each",
			region: "us-east-1",
			assumeRoles: []config.AssumeRoleConfig{
				{RoleARN: "arn:aws:iam::111111111111:role/a", Region: "us-west-2"},
				{RoleARN: "arn:aws:iam::222222222222:role/b", Region: "eu-west-1"},
			},
			want: []inventoryPass{
				{region: "us-west-2", assumeRoleARN: "arn:aws:iam::111111111111:role/a"},
				{region: "eu-west-1", assumeRoleARN: "arn:aws:iam::222222222222:role/b"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildInventoryPasses(tt.region, tt.assumeRoles))
		})
	}
}

// failingCredsProvider is an aws.CredentialsProvider whose Retrieve always fails, used to simulate
// unresolvable/unauthorized credentials in startup validation tests.
type failingCredsProvider struct{}

func (failingCredsProvider) Retrieve(_ context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, errors.New("boom: could not retrieve credentials")
}

func configWithCreds(region string, workingCreds bool) aws.Config {
	cfg := aws.Config{Region: region}
	if workingCreds {
		cfg.Credentials = credentials.NewStaticCredentialsProvider("AKID", "SECRET", "TOKEN")
	} else {
		cfg.Credentials = failingCredsProvider{}
	}
	return cfg
}

func TestPreparePasses(t *testing.T) {
	SetLogger(&mockLogger{})

	roleARN := "arn:aws:iam::123456789012:role/foo"

	tests := []struct {
		name        string
		passes      []inventoryPass
		build       awsConfigBuilder
		wantReady   int
		wantRegions []string // when set, the region stored on each ready pass, in order
		wantErr     bool
	}{
		{
			name:   "ambient pass with resolvable region is ready even without pre-flighting credentials",
			passes: []inventoryPass{{region: "us-east-1"}},
			// Credentials deliberately fail: the ambient pass must NOT fail startup on a credential
			// blip (regression guard); it warns and stays ready.
			build: func(_ context.Context, region, _, _ string) (aws.Config, error) {
				return configWithCreds(region, false), nil
			},
			wantReady: 1,
		},
		{
			// Regression guard for the "logs report region=''" bug: when the region is resolved by the
			// SDK (AWS_REGION / instance metadata) rather than configured, the ready pass must carry the
			// RESOLVED region so every downstream log/tracker line is accurate. Fails if preparePasses
			// stores the (empty) configured region instead of cfg.Region.
			name:   "ambient pass stores the SDK-resolved region, not the empty configured one",
			passes: []inventoryPass{{region: ""}},
			build: func(_ context.Context, _, _, _ string) (aws.Config, error) {
				return configWithCreds("us-east-1", true), nil
			},
			wantReady:   1,
			wantRegions: []string{"us-east-1"},
		},
		{
			name:   "ambient pass with no resolvable region fails startup",
			passes: []inventoryPass{{region: ""}},
			build: func(_ context.Context, _, _, _ string) (aws.Config, error) {
				// SDK resolved no region anywhere (no config/flag/env/IMDS).
				return configWithCreds("", true), nil
			},
			wantErr: true,
		},
		{
			name:   "assume-role pass with valid credentials and region is ready",
			passes: []inventoryPass{{region: "us-west-2", assumeRoleARN: roleARN}},
			build: func(_ context.Context, region, _, _ string) (aws.Config, error) {
				return configWithCreds(region, true), nil
			},
			wantReady: 1,
		},
		{
			name:   "assume-role pass with failing credentials fails startup",
			passes: []inventoryPass{{region: "us-west-2", assumeRoleARN: roleARN}},
			build: func(_ context.Context, region, _, _ string) (aws.Config, error) {
				return configWithCreds(region, false), nil
			},
			wantErr: true,
		},
		{
			name:   "config build error fails startup",
			passes: []inventoryPass{{region: "us-east-1"}},
			build: func(_ context.Context, _, _, _ string) (aws.Config, error) {
				return aws.Config{}, errors.New("could not load config")
			},
			wantErr: true,
		},
		{
			name: "one bad assume-role pass fails the whole startup",
			passes: []inventoryPass{
				{region: "us-west-2", assumeRoleARN: roleARN},
				{region: "eu-west-1", assumeRoleARN: "arn:aws:iam::999999999999:role/bar"},
			},
			build: func(_ context.Context, region, _, _ string) (aws.Config, error) {
				return configWithCreds(region, region == "us-west-2"), nil
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ready, err := preparePasses(context.Background(), tt.build, tt.passes)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, ready)
				return
			}
			assert.NoError(t, err)
			assert.Len(t, ready, tt.wantReady)
			if tt.wantRegions != nil {
				gotRegions := make([]string, len(ready))
				for i, r := range ready {
					gotRegions[i] = r.region
				}
				assert.Equal(t, tt.wantRegions, gotRegions, "ready passes should carry the SDK-resolved region")
			}
		})
	}
}

// TestPreparePassesWarnsButDoesNotFailOnAmbientCredentialFailure guards N5: the ambient pass gets a
// friendly credential warning at startup (restoring the old checkAWSCredentials diagnostic) but is
// NOT failed, so a transient blip does not stop the agent from starting and retrying.
func TestPreparePassesWarnsButDoesNotFailOnAmbientCredentialFailure(t *testing.T) {
	rec := &recordingLogger{}
	SetLogger(rec)
	defer SetLogger(&mockLogger{})

	ready, err := preparePasses(context.Background(),
		func(_ context.Context, region, _, _ string) (aws.Config, error) {
			return configWithCreds(region, false), nil // creds cannot be retrieved
		},
		[]inventoryPass{{region: "us-east-1"}})

	require.NoError(t, err, "an ambient credential blip must not fail startup")
	require.Len(t, ready, 1)
	assert.True(t, containsSubstr(rec.warns, "Could not resolve AWS credentials for the ambient inventory pass"),
		"expected a friendly ambient-credential warning; got warns=%v", rec.warns)
}

// TestCycleOverran guards N4's slow-cycle detection: strictly greater than the interval overruns.
func TestCycleOverran(t *testing.T) {
	assert.False(t, cycleOverran(5*time.Second, 300), "a fast cycle does not overrun")
	assert.False(t, cycleOverran(300*time.Second, 300), "a cycle exactly at the interval does not overrun")
	assert.True(t, cycleOverran(301*time.Second, 300), "a cycle past the interval overruns")
}
