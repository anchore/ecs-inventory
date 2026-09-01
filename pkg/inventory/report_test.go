package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/h2non/gock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/ecs-inventory/internal"
	"github.com/anchore/ecs-inventory/internal/logger"
	"github.com/anchore/ecs-inventory/pkg/connection"
	"github.com/anchore/ecs-inventory/pkg/reporter"
)

func init() {
	logger.Log = &logger.NoOpLogger{}
}

func TestConfigureAssumeRoleSetsCredentialsCacheWhenARNSet(t *testing.T) {
	// A non-empty ARN should swap in an STS assume-role credentials cache.
	base := aws.Config{}
	cfg, assumed := configureAssumeRole(base, "arn:aws:iam::123456789012:role/foo", "ext-id")

	assert.True(t, assumed)
	_, ok := cfg.Credentials.(*aws.CredentialsCache)
	assert.True(t, ok, "expected credentials to be an *aws.CredentialsCache")
}

func TestConfigureAssumeRoleSkippedWhenNoARN(t *testing.T) {
	// With no ARN the config is returned untouched so ambient credentials are used.
	base := aws.Config{}
	cfg, assumed := configureAssumeRole(base, "", "")

	assert.False(t, assumed)
	assert.Nil(t, cfg.Credentials, "expected credentials to be left unchanged when no role is assumed")
}

func TestAssumeRoleOptionsCarryARNSessionAndExternalID(t *testing.T) {
	// External ID is passed through to the STS options when set.
	var opts stscreds.AssumeRoleOptions
	assumeRoleOptionsFor("ext-id")(&opts)

	assert.Equal(t, internal.ApplicationName, opts.RoleSessionName)
	require.NotNil(t, opts.ExternalID)
	assert.Equal(t, "ext-id", *opts.ExternalID)
}

func TestAssumeRoleOptionsOmitEmptyExternalID(t *testing.T) {
	// An empty external ID must not be sent (nil), since AWS rejects a blank value.
	var opts stscreds.AssumeRoleOptions
	assumeRoleOptionsFor("")(&opts)

	assert.Equal(t, internal.ApplicationName, opts.RoleSessionName)
	assert.Nil(t, opts.ExternalID)
}

func TestGetInventoryReportForCluster(t *testing.T) {
	mockSvc := &mockECSClient{}

	report, err := GetInventoryReportForCluster(context.Background(), "cluster-1", mockSvc, "")

	assert.NoError(t, err)
	assert.Equal(t, 4, len(report.Containers))
}

func TestHandleReport(t *testing.T) {
	testReport := reporter.Report{
		Timestamp:  "2024-01-01T00:00:00Z",
		ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/test",
		Containers: []reporter.Container{
			{
				ARN:         "arn:aws:ecs:us-east-1:123456789012:container/abc",
				ImageTag:    "nginx:latest",
				ImageDigest: "sha256:abc123",
				TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/test/task1",
			},
		},
	}

	validAnchore := connection.AnchoreInfo{
		URL:      "https://ancho.re",
		User:     "admin",
		Password: "foobar",
		Account:  "test",
		HTTP: connection.HTTPConfig{
			TimeoutSeconds: 10,
			Insecure:       true,
		},
	}

	invalidAnchore := connection.AnchoreInfo{}

	t.Run("dry run does not post or print", func(t *testing.T) {
		err := HandleReport(testReport, validAnchore, true, true)
		assert.NoError(t, err)
	})

	t.Run("valid anchore quiet posts to anchore", func(t *testing.T) {
		defer gock.Off()
		gock.New("https://ancho.re").
			Post("v2/ecs-inventory").
			Reply(201).
			JSON(map[string]interface{}{})

		err := HandleReport(testReport, validAnchore, true, false)
		assert.NoError(t, err)
		assert.True(t, gock.IsDone())
	})

	t.Run("invalid anchore not quiet prints to stdout", func(t *testing.T) {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := HandleReport(testReport, invalidAnchore, false, false)

		w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		buf.ReadFrom(r)
		output := buf.String()

		assert.NoError(t, err)
		assert.Contains(t, output, testReport.ClusterARN)
	})

	t.Run("invalid anchore quiet does not print", func(t *testing.T) {
		err := HandleReport(testReport, invalidAnchore, true, false)
		assert.NoError(t, err)
	})

	// Guards the startup-log accuracy fix: "Reporting results to Anchore" must be logged only when a
	// report is actually sent, never on the dry-run or no-Anchore paths (and, by living here rather
	// than in reporter.Post, never during the startup credential-validation dummy post).
	t.Run("announces reporting only when it actually reports", func(t *testing.T) {
		rec := &recordingLogger{}
		old := logger.Log
		logger.Log = rec
		defer func() { logger.Log = old }()

		require.NoError(t, HandleReport(testReport, validAnchore, true, true))    // dry run
		require.NoError(t, HandleReport(testReport, invalidAnchore, true, false)) // no valid Anchore
		assert.NotContains(t, rec.infos, "Reporting results to Anchore",
			"must not announce reporting when nothing was sent")

		rec.infos = nil
		defer gock.Off()
		gock.New("https://ancho.re").Post("v2/ecs-inventory").Reply(201).JSON(map[string]interface{}{})
		require.NoError(t, HandleReport(testReport, validAnchore, true, false))
		assert.Contains(t, rec.infos, "Reporting results to Anchore", "must announce reporting on the real path")
	})
}

// recordingLogger captures Info and Warn messages so tests can assert on what was actually logged;
// all other levels fall through to the embedded no-op logger.
type recordingLogger struct {
	logger.NoOpLogger
	infos []string
	warns []string
}

func (r *recordingLogger) Info(msg string, args ...interface{}) { r.infos = append(r.infos, msg) }
func (r *recordingLogger) Warn(msg string, args ...interface{}) { r.warns = append(r.warns, msg) }

// TestHandleReport_OfflineModeWhenAnchoreOmitted documents ecs-inventory's implicit "offline mode":
// like k8s-inventory, omitting the Anchore Enterprise API details (so IsValid is false) makes the
// agent still gather inventory but skip reporting -- printing to stdout unless quiet, and never
// attempting a post. This locks that contract so it isn't lost accidentally.
func TestHandleReport_OfflineModeWhenAnchoreOmitted(t *testing.T) {
	offline := connection.AnchoreInfo{} // no URL/User/Password => offline
	require.False(t, offline.IsValid(), "omitting Anchore details must be treated as offline")

	report := reporter.Report{
		Timestamp:  "2024-01-01T00:00:00Z",
		ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/offline",
		Containers: []reporter.Container{{ARN: "arn:aws:ecs:us-east-1:123456789012:container/x", ImageTag: "nginx:1.25"}},
	}

	capture := func(t *testing.T, quiet bool) (stdout string, rec *recordingLogger) {
		t.Helper()
		rec = &recordingLogger{}
		old := logger.Log
		logger.Log = rec
		defer func() { logger.Log = old }()

		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		err := HandleReport(report, offline, quiet, false)
		w.Close()
		os.Stdout = oldStdout
		var buf bytes.Buffer
		buf.ReadFrom(r)

		require.NoError(t, err, "offline mode must not error")
		// In every offline case the agent must announce it is not reporting and must NOT claim to.
		assert.Contains(t, rec.warns, "Anchore details not specified, not reporting inventory")
		assert.NotContains(t, rec.infos, "Reporting results to Anchore", "offline mode must not report")
		return buf.String(), rec
	}

	t.Run("not quiet prints inventory to stdout", func(t *testing.T) {
		out, _ := capture(t, false)
		assert.Contains(t, out, report.ClusterARN, "offline non-quiet should still emit inventory to stdout")
	})

	t.Run("quiet emits nothing", func(t *testing.T) {
		out, _ := capture(t, true)
		assert.Empty(t, out, "offline quiet should print nothing")
	})
}

func Test_reportToStdout(t *testing.T) {
	testReport := reporter.Report{
		Timestamp:  "2024-01-01T00:00:00Z",
		ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/test",
		Containers: []reporter.Container{
			{
				ARN:         "arn:aws:ecs:us-east-1:123456789012:container/abc",
				ImageTag:    "nginx:latest",
				ImageDigest: "sha256:abc123",
				TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/test/task1",
			},
		},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := reportToStdout(testReport)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	require.NoError(t, err)

	var decoded reporter.Report
	err = json.Unmarshal([]byte(output), &decoded)
	require.NoError(t, err)
	assert.Equal(t, testReport.ClusterARN, decoded.ClusterARN)
	assert.Equal(t, testReport.Timestamp, decoded.Timestamp)
	assert.Len(t, decoded.Containers, 1)
	assert.Equal(t, "nginx:latest", decoded.Containers[0].ImageTag)
}

func Test_ensureReferencedObjectsExist(t *testing.T) {
	type args struct {
		report reporter.Report
	}
	tests := []struct {
		name string
		args args
		want reporter.Report
	}{
		{
			name: "no missing objects",
			args: args{
				report: reporter.Report{
					Containers: []reporter.Container{
						{
							ARN:         "arn:aws:ecs:us-east-1:123456789012:container/container-1",
							TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
							ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678901234",
							ImageTag:    "latest",
						},
					},
					Tasks: []reporter.Task{
						{
							ARN:        "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
							TaskDefARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/taskdef-1",
							ServiceARN: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
							Tags: map[string]string{
								"tag1": "value1",
							},
						},
					},
					Services: []reporter.Service{
						{
							ARN: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
							Tags: map[string]string{
								"tag1": "value1",
							},
						},
					},
					Timestamp:  "2023-06-15T00:00:00Z",
					ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
				},
			},
			want: reporter.Report{
				Containers: []reporter.Container{
					{
						ARN:         "arn:aws:ecs:us-east-1:123456789012:container/container-1",
						TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
						ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678901234",
						ImageTag:    "latest",
					},
				},
				Tasks: []reporter.Task{
					{
						ARN:        "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
						TaskDefARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/taskdef-1",
						ServiceARN: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
						Tags: map[string]string{
							"tag1": "value1",
						},
					},
				},
				Services: []reporter.Service{
					{
						ARN: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
						Tags: map[string]string{
							"tag1": "value1",
						},
					},
				},
				Timestamp:  "2023-06-15T00:00:00Z",
				ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
			},
		},
		{
			name: "missing service object",
			args: args{
				report: reporter.Report{
					Containers: []reporter.Container{
						{
							ARN:         "arn:aws:ecs:us-east-1:123456789012:container/container-1",
							TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
							ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678901234",
							ImageTag:    "latest",
						},
					},
					Tasks: []reporter.Task{
						{
							ARN:        "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
							TaskDefARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/taskdef-1",
							ServiceARN: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
							Tags: map[string]string{
								"tag1": "value1",
							},
						},
					},
					Services:   []reporter.Service{},
					Timestamp:  "2023-06-15T00:00:00Z",
					ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
				},
			},
			want: reporter.Report{
				Containers: []reporter.Container{
					{
						ARN:         "arn:aws:ecs:us-east-1:123456789012:container/container-1",
						TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
						ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678901234",
						ImageTag:    "latest",
					},
				},
				Tasks: []reporter.Task{
					{
						ARN:        "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
						TaskDefARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/taskdef-1",
						ServiceARN: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
						Tags: map[string]string{
							"tag1": "value1",
						},
					},
				},
				Services: []reporter.Service{
					{
						ARN: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
					},
				},
				Timestamp:  "2023-06-15T00:00:00Z",
				ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
			},
		},
		{
			name: "missing task object",
			args: args{
				report: reporter.Report{
					Containers: []reporter.Container{
						{
							ARN:         "arn:aws:ecs:us-east-1:123456789012:container/container-1",
							TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
							ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678901234",
							ImageTag:    "latest",
						},
					},
					Tasks:      []reporter.Task{},
					Timestamp:  "2023-06-15T00:00:00Z",
					ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
				},
			},
			want: reporter.Report{
				Containers: []reporter.Container{
					{
						ARN:         "arn:aws:ecs:us-east-1:123456789012:container/container-1",
						TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
						ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678901234",
						ImageTag:    "latest",
					},
				},
				Tasks: []reporter.Task{
					{
						ARN:        "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
						TaskDefARN: "UNKNOWN",
					},
				},
				Timestamp:  "2023-06-15T00:00:00Z",
				ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
			},
		},
		{
			name: "mix of standalone tasks and tasks in services",
			args: args{
				report: reporter.Report{
					Containers: []reporter.Container{
						{
							ARN:         "arn:aws:ecs:us-east-1:123456789012:container/container-1",
							TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
							ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678901234",
							ImageTag:    "latest",
						},
						{
							ARN:         "arn:aws:ecs:us-east-1:123456789012:container/container-2",
							TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000001",
							ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678901234",
							ImageTag:    "latest",
						},
					},
					Tasks: []reporter.Task{
						{
							ARN:        "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
							TaskDefARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/taskdef-1",
							ServiceARN: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
							Tags: map[string]string{
								"tag1": "value1",
							},
						},
						{
							ARN:        "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000001",
							TaskDefARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/taskdef-2",
							Tags: map[string]string{
								"tag1": "value1",
							},
						},
					},
					Services: []reporter.Service{
						{
							ARN: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
							Tags: map[string]string{
								"tag1": "value1",
							},
						},
					},
					Timestamp:  "2023-06-15T00:00:00Z",
					ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
				},
			},
			want: reporter.Report{
				Containers: []reporter.Container{
					{
						ARN:         "arn:aws:ecs:us-east-1:123456789012:container/container-1",
						TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
						ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678901234",
						ImageTag:    "latest",
					},
					{
						ARN:         "arn:aws:ecs:us-east-1:123456789012:container/container-2",
						TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000001",
						ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678901234",
						ImageTag:    "latest",
					},
				},
				Tasks: []reporter.Task{
					{
						ARN:        "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
						TaskDefARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/taskdef-1",
						ServiceARN: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
						Tags: map[string]string{
							"tag1": "value1",
						},
					},
					{
						ARN:        "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000001",
						TaskDefARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/taskdef-2",
						ServiceARN: "UNKNOWN",
						Tags: map[string]string{
							"tag1": "value1",
						},
					},
				},
				Services: []reporter.Service{
					{
						ARN: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
						Tags: map[string]string{
							"tag1": "value1",
						},
					},
					{
						ARN:  "UNKNOWN",
						Tags: nil,
					},
				},
				Timestamp:  "2023-06-15T00:00:00Z",
				ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ensureReferencedObjectsExist(tt.args.report)
			assert.Equal(t, tt.want, got)
		})
	}
}
