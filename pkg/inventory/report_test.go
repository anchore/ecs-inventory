package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/ecs-inventory/internal/logger"
	"github.com/anchore/ecs-inventory/pkg/connection"
	"github.com/anchore/ecs-inventory/pkg/reporter"
)

func init() {
	logger.Log = &logger.NoOpLogger{}
}

func TestGetInventoryReportForCluster(t *testing.T) {
	mockSvc := &mockECSClient{}

	report, err := GetInventoryReportForCluster(context.Background(), "cluster-1", mockSvc)

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
