package inventory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/ecs-inventory/pkg/reporter"
)

func TestGetInventoryReportForCluster(t *testing.T) {
	mockSvc := &mockECSClient{}

	report, err := GetInventoryReportForCluster(context.Background(), "cluster-1", mockSvc)

	assert.NoError(t, err)
	assert.Equal(t, 4, len(report.Containers))
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
