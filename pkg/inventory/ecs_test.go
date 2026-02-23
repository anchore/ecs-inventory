package inventory

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/ecs-inventory/pkg/reporter"
)

func Test_fetchClusters(t *testing.T) {
	type args struct {
		client ECSAPI
	}
	tests := []struct {
		name    string
		args    args
		want    []string
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
			want: []string{
				"arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
				"arn:aws:ecs:us-east-1:123456789012:cluster/cluster-2",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetchClusters(context.Background(), tt.args.client)
			if (err != nil) != tt.wantErr {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_fetchTasksFromCluster(t *testing.T) {
	type args struct {
		client  ECSAPI
		cluster string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
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
			want: []string{
				"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
				"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetchTasksFromCluster(context.Background(), tt.args.client, tt.args.cluster)
			if (err != nil) != tt.wantErr {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_fetchContainersFromTasks(t *testing.T) {
	type args struct {
		client  ECSAPI
		cluster string
		tasks   []string
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
				tasks: []string{
					"BAD-ARN",
				},
			},
			wantErr: true,
		},
		{
			name: "successfully return containers for single task",
			args: args{
				client:  &mockECSClient{},
				cluster: "cluster-1",
				tasks: []string{
					"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
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
				tasks: []string{
					"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
					"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111",
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
			got, err := fetchContainersFromTasks(context.Background(), tt.args.client, tt.args.cluster, tt.args.tasks)
			if (err != nil) != tt.wantErr {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_fetchTasksMetadata(t *testing.T) {
	type args struct {
		client  ECSAPI
		cluster string
		tasks   []string
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
				tasks: []string{
					"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
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
				tasks: []string{
					"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
				},
			},
			wantErr: true,
		},
		{
			name: "successfully return tasks metadata",
			args: args{
				client:  &mockECSClient{},
				cluster: "cluster-1",
				tasks: []string{
					"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
					"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111",
				},
			},
			want: []reporter.Task{
				{
					ARN:        "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
					ServiceARN: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
					TaskDefARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/task-definition-1:1",
					Tags: map[string]string{
						"key-1": "value-1",
						"key-2": "value-2",
					},
				},
				{
					ARN:        "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111",
					ServiceARN: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
					TaskDefARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/task-definition-1:1",
					Tags:       map[string]string{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetchTasksMetadata(context.Background(), tt.args.client, tt.args.cluster, tt.args.tasks)
			if (err != nil) != tt.wantErr {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_fetchTagsForResource(t *testing.T) {
	type args struct {
		client      ECSAPI
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
			got, err := fetchTagsForResource(context.Background(), tt.args.client, tt.args.resourceARN)
			if (err != nil) != tt.wantErr {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_fetchServicesFromCluster(t *testing.T) {
	type args struct {
		client  ECSAPI
		cluster string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
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
			want: []string{
				"arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
				"arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-2",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetchServicesFromCluster(context.Background(), tt.args.client, tt.args.cluster)
			if (err != nil) != tt.wantErr {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_fetchServicesMetadata(t *testing.T) {
	type args struct {
		client   ECSAPI
		cluster  string
		services []string
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
				services: []string{
					"arn",
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
				services: []string{
					"arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
				},
			},
			wantErr: true,
		},
		{
			name: "successfully return services",
			args: args{
				client:  &mockECSClient{},
				cluster: "cluster-1",
				services: []string{
					"arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
					"arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-2",
				},
			},
			want: []reporter.Service{
				{
					ARN: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
					Tags: map[string]string{
						"svc-key-1": "svc-value-1",
						"svc-key-2": "svc-value-2",
					},
				},
				{
					ARN:  "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-2",
					Tags: map[string]string{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetchServicesMetadata(context.Background(), tt.args.client, tt.args.cluster, tt.args.services)
			if (err != nil) != tt.wantErr {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_constructServiceARN(t *testing.T) {
	type args struct {
		clusterARN string
		service    string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "successfully construct service arn from valid cluster arn",
			args: args{
				clusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
				service:    "service-1",
			},
			want: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
		},
		{
			name: "return error when cluster arn is invalid",
			args: args{
				clusterARN: "invali:/d-arn",
				service:    "service-1",
			},
			wantErr: true,
		},
		{
			name: "return error when cluster arn is invalid",
			args: args{
				clusterARN: "arn:aws:ecs:us-east-1:123456789012:clustercluster-1",
				service:    "service-1",
			},
			wantErr: true,
		},
		{
			name: "return error when cluster arn is invalid",
			args: args{
				clusterARN: "arn:aws:ecs:::/",
				service:    "service-1",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := constructServiceARN(tt.args.clusterARN, tt.args.service)
			if (err != nil) != tt.wantErr {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_buildContainerTagMap(t *testing.T) {
	tests := []struct {
		name  string
		tasks []ecstypes.Task
		want  map[string]string
	}{
		{
			name:  "empty task list",
			tasks: []ecstypes.Task{},
			want:  map[string]string{},
		},
		{
			name: "containers with @ in image are excluded",
			tasks: []ecstypes.Task{
				{
					Containers: []ecstypes.Container{
						{
							Image:       aws.String("image-1@sha256:abc123"),
							ImageDigest: aws.String("sha256:abc123"),
						},
					},
				},
			},
			want: map[string]string{},
		},
		{
			name: "containers with clean image tags are included",
			tasks: []ecstypes.Task{
				{
					Containers: []ecstypes.Container{
						{
							Image:       aws.String("nginx:latest"),
							ImageDigest: aws.String("sha256:abc123"),
						},
						{
							Image:       aws.String("redis:7.0"),
							ImageDigest: aws.String("sha256:def456"),
						},
					},
				},
			},
			want: map[string]string{
				"sha256:abc123": "nginx:latest",
				"sha256:def456": "redis:7.0",
			},
		},
		{
			name: "mix of clean and @ images",
			tasks: []ecstypes.Task{
				{
					Containers: []ecstypes.Container{
						{
							Image:       aws.String("nginx:latest"),
							ImageDigest: aws.String("sha256:abc123"),
						},
						{
							Image:       aws.String("redis@sha256:def456"),
							ImageDigest: aws.String("sha256:def456"),
						},
					},
				},
			},
			want: map[string]string{
				"sha256:abc123": "nginx:latest",
			},
		},
		{
			name: "nil image digest is skipped",
			tasks: []ecstypes.Task{
				{
					Containers: []ecstypes.Container{
						{
							Image:       aws.String("nginx:latest"),
							ImageDigest: nil,
						},
					},
				},
			},
			want: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildContainerTagMap(tt.tasks)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_getContainerImageTag(t *testing.T) {
	type args struct {
		containerTagMap map[string]string
		container       ecstypes.Container
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "return container image tag when it does not contain @ symbol",
			args: args{
				containerTagMap: map[string]string{
					"sha256:1234567890123456789012345678901234567890123456789012345678901111": "image-1:latest",
					"sha256:1234567890123456789012345678901234567890123456789012345678902222": "image-2:latest",
				},
				container: ecstypes.Container{
					Image:       aws.String("image-1:latest"),
					ImageDigest: aws.String("sha256:1234567890123456789012345678901234567890123456789012345678901111"),
				},
			},
			want: "image-1:latest",
		},
		{
			name: "return container image tag from map when it does contain @ symbol",
			args: args{
				containerTagMap: map[string]string{
					"sha256:1234567890123456789012345678901234567890123456789012345678901111": "image-1:latest",
					"sha256:1234567890123456789012345678901234567890123456789012345678902222": "image-2:latest",
				},
				container: ecstypes.Container{
					Image:       aws.String("image-1@sha256:1234567890123456789012345678901234567890123456789012345678901111"),
					ImageDigest: aws.String("sha256:1234567890123456789012345678901234567890123456789012345678901111"),
				},
			},
			want: "image-1:latest",
		},
		{
			name: "return UNKNOWN as the tag when image tag is not found in the map",
			args: args{
				containerTagMap: map[string]string{
					"sha256:1234567890123456789012345678901234567890123456789012345678901111": "image-1:latest",
					"sha256:1234567890123456789012345678901234567890123456789012345678902222": "image-2:latest",
				},
				container: ecstypes.Container{
					Image:       aws.String("image-1@sha256:0000"),
					ImageDigest: aws.String("sha256:11"),
				},
			},
			want: "image-1:UNKNOWN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getContainerImageTag(tt.args.containerTagMap, &tt.args.container)
			assert.Equal(t, tt.want, got)
		})
	}
}
