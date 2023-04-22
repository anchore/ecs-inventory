package inventory

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs/ecsiface"
	"github.com/stretchr/testify/assert"
)

func TestFetchClusters(t *testing.T) {
	mockSvc := &mockECSClient{}

	clusters, err := fetchClusters(mockSvc)

	assert.NoError(t, err)
	assert.Equal(t, 2, len(clusters))
}

func TestFetchTasksFromCluster(t *testing.T) {
	mockSvc := &mockECSClient{}

	tasks, err := fetchTasksFromCluster(mockSvc, "cluster-1")

	assert.NoError(t, err)
	assert.Equal(t, 2, len(tasks))
}

func TestFetchContainersFromTasks(t *testing.T) {
	mockSvc := &mockECSClient{}

	containers, err := fetchContainersFromTasks(mockSvc, "cluster-1", []*string{
		aws.String("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000"),
		aws.String("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111"),
	})

	assert.NoError(t, err)
	assert.Equal(t, 4, len(containers))
}

func TestFetchTasksMetadata(t *testing.T) {
	mockSvc := &mockECSClient{}

	tasksMeta, err := fetchTasksMetadata(mockSvc, "cluster-1", []*string{
		aws.String("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000"),
		aws.String("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111"),
	})

	assert.NoError(t, err)
	assert.Equal(t, 2, len(tasksMeta))
}

func TestFetchTagsForResource(t *testing.T) {
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
				t.Errorf("fetchTagsForResource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fetchTagsForResource() = %v, want %v", got, tt.want)
			}
		})
	}
}
