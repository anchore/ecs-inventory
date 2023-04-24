package inventory

import (
	"testing"

	"github.com/anchore/ecs-inventory/pkg/reporter"
	"github.com/aws/aws-sdk-go/service/ecs/ecsiface"
	"github.com/stretchr/testify/assert"
)

// Return a pointer to the passed value
func GetPointerToValue[T any](t T) *T { return &t }

func Test_fetchClusters(t *testing.T) {
	type args struct {
		client ecsiface.ECSAPI
	}
	tests := []struct {
		name    string
		args    args
		want    []*string
		wantErr bool
	}{
		{
			name: "on error return error",
			args: args{
				client: &mockECSClient{
					ErrorOnListCluster: true,
				},
			},
			wantErr: true,
		},
		{
			name: "successfully return clusters",
			args: args{
				client: &mockECSClient{},
			},
			want: []*string{
				GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1"),
				GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:cluster/cluster-2"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetchClusters(tt.args.client)
			if (err != nil) != tt.wantErr {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_fetchTasksFromCluster(t *testing.T) {
	type args struct {
		client  ecsiface.ECSAPI
		cluster string
	}
	tests := []struct {
		name    string
		args    args
		want    []*string
		wantErr bool
	}{
		{
			name: "on error return error",
			args: args{
				client: &mockECSClient{
					ErrorOnListTasks: true,
				},
			},
			wantErr: true,
		},
		{
			name: "successfully return tasks",
			args: args{
				client:  &mockECSClient{},
				cluster: "cluster-1",
			},
			want: []*string{
				GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000"),
				GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetchTasksFromCluster(tt.args.client, tt.args.cluster)
			if (err != nil) != tt.wantErr {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_fetchContainersFromTasks(t *testing.T) {
	type args struct {
		client  ecsiface.ECSAPI
		cluster string
		tasks   []*string
	}
	tests := []struct {
		name    string
		args    args
		want    []reporter.Container
		wantErr bool
	}{
		{
			name: "on error return error",
			args: args{
				client: &mockECSClient{
					ErrorOnDescribeTasks: true,
				},
				cluster: "cluster-1",
				tasks: []*string{
					GetPointerToValue("BAD-ARN"),
				},
			},
			wantErr: true,
		},
		{
			name: "successfully return containers for single task",
			args: args{
				client:  &mockECSClient{},
				cluster: "cluster-1",
				tasks: []*string{
					GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000"),
				},
			},
			want: []reporter.Container{
				{
					ARN:         "arn:aws:ecs:us-east-1:123456789012:container/12345678-1234-1234-1234-111111111111",
					ImageTag:    "image-1",
					ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678901111",
					TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
				},
				{
					ARN:         "arn:aws:ecs:us-east-1:123456789012:container/12345678-1234-1234-1234-111111111112",
					ImageTag:    "image-2",
					ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678902222",
					TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
				},
			},
		},
		{
			name: "successfully return containers for multiple tasks",
			args: args{
				client:  &mockECSClient{},
				cluster: "cluster-1",
				tasks: []*string{
					GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000"),
					GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111"),
				},
			},
			want: []reporter.Container{
				{
					ARN:         "arn:aws:ecs:us-east-1:123456789012:container/12345678-1234-1234-1234-111111111111",
					ImageTag:    "image-1",
					ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678901111",
					TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
				},
				{
					ARN:         "arn:aws:ecs:us-east-1:123456789012:container/12345678-1234-1234-1234-111111111112",
					ImageTag:    "image-2",
					ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678902222",
					TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
				},
				{
					ARN:         "arn:aws:ecs:us-east-1:123456789012:container/12345678-1234-1234-1234-111111111113",
					ImageTag:    "image-3",
					ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678903333",
					TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111",
				},
				{
					ARN:         "arn:aws:ecs:us-east-1:123456789012:container/12345678-1234-1234-1234-111111111114",
					ImageTag:    "image-3",
					ImageDigest: "sha256:1234567890123456789012345678901234567890123456789012345678903333",
					TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetchContainersFromTasks(tt.args.client, tt.args.cluster, tt.args.tasks)
			if (err != nil) != tt.wantErr {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_fetchTasksMetadata(t *testing.T) {
	type args struct {
		client  ecsiface.ECSAPI
		cluster string
		tasks   []*string
	}
	tests := []struct {
		name    string
		args    args
		want    []reporter.Task
		wantErr bool
	}{
		{
			name: "return error when describe tasks fails",
			args: args{
				client: &mockECSClient{
					ErrorOnDescribeTasks: true,
				},
				cluster: "cluster-1",
				tasks: []*string{
					GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000"),
				},
			},
			wantErr: true,
		},
		{
			name: "return error when list tags fails",
			args: args{
				client: &mockECSClient{
					ErrorOnListTagsForResource: true,
				},
				cluster: "cluster-1",
				tasks: []*string{
					GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000"),
				},
			},
			wantErr: true,
		},
		{
			name: "successfully return tasks metadata",
			args: args{
				client:  &mockECSClient{},
				cluster: "cluster-1",
				tasks: []*string{
					GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000"),
					GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111"),
				},
			},
			want: []reporter.Task{
				{
					ARN:        "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
					ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
					TaskDefARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/task-definition-1:1",
					Tags: map[string]string{
						"key-1": "value-1",
						"key-2": "value-2",
					},
				},
				{
					ARN:        "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111",
					ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
					TaskDefARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/task-definition-1:1",
					Tags:       map[string]string{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetchTasksMetadata(tt.args.client, tt.args.cluster, tt.args.tasks)
			if (err != nil) != tt.wantErr {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_fetchTagsForResource(t *testing.T) {
	type args struct {
		client      ecsiface.ECSAPI
		resourceARN string
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]string
		wantErr bool
	}{
		{
			name: "on error return error",
			args: args{
				client: &mockECSClient{
					ErrorOnListTagsForResource: true,
				},
				resourceARN: "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
			},
			wantErr: true,
		},
		{
			name: "on invalid arn receive empty map",
			args: args{
				client:      &mockECSClient{},
				resourceARN: "BADARN",
			},
			want: map[string]string{},
		},
		{
			name: "valid arn",
			args: args{
				client:      &mockECSClient{},
				resourceARN: "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
			},
			want: map[string]string{
				"key-1": "value-1",
				"key-2": "value-2",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetchTagsForResource(tt.args.client, tt.args.resourceARN)
			if (err != nil) != tt.wantErr {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_fetchServicesFromCluster(t *testing.T) {
	type args struct {
		client  ecsiface.ECSAPI
		cluster string
	}
	tests := []struct {
		name    string
		args    args
		want    []*string
		wantErr bool
	}{
		{
			name: "return error when list services fails",
			args: args{
				client: &mockECSClient{
					ErrorOnListServices: true,
				},
				cluster: "cluster-1",
			},
			wantErr: true,
		},
		{
			name: "successfully return services",
			args: args{
				client:  &mockECSClient{},
				cluster: "cluster-1",
			},
			want: []*string{
				GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1"),
				GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-2"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetchServicesFromCluster(tt.args.client, tt.args.cluster)
			if (err != nil) != tt.wantErr {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_fetchServicesMetadata(t *testing.T) {
	type args struct {
		client   ecsiface.ECSAPI
		cluster  string
		services []*string
	}
	tests := []struct {
		name    string
		args    args
		want    []reporter.Service
		wantErr bool
	}{
		{
			name: "return error when describe services fails",
			args: args{
				client: &mockECSClient{
					ErrorOnDescribeServices: true,
				},
				cluster: "cluster-1",
				services: []*string{
					GetPointerToValue("arn"),
				},
			},
			wantErr: true,
		},
		{
			name: "return error when list tags for resource fails",
			args: args{
				client: &mockECSClient{
					ErrorOnListTagsForResource: true,
				},
				cluster: "cluster-1",
				services: []*string{
					GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1"),
				},
			},
			wantErr: true,
		},
		{
			name: "successfully return services",
			args: args{
				client:  &mockECSClient{},
				cluster: "cluster-1",
				services: []*string{
					GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1"),
					GetPointerToValue("arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-2"),
				},
			},
			want: []reporter.Service{
				{
					ARN:        "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
					ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
					Tags: map[string]string{
						"svc-key-1": "svc-value-1",
						"svc-key-2": "svc-value-2",
					},
				},
				{
					ARN:        "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-2",
					ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
					Tags:       map[string]string{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetchServicesMetadata(tt.args.client, tt.args.cluster, tt.args.services)
			if (err != nil) != tt.wantErr {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
