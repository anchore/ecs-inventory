package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

const taskMetadataFixture = `{
  "Cluster": "arn:aws:ecs:us-east-1:123456789012:cluster/agent-cluster",
  "TaskARN": "arn:aws:ecs:us-east-1:123456789012:task/agent-cluster/abc123",
  "Family": "anchore-ecs-inventory",
  "ServiceName": "anchore-ecs-inventory-service",
  "Revision": "7",
  "DesiredStatus": "RUNNING",
  "Containers": []
}`

func TestGetTaskMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/task", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(taskMetadataFixture))
	}))
	defer server.Close()

	t.Setenv(metadataURIEnvVarV4, server.URL)

	got := GetTaskMetadata(context.Background())

	assert.Equal(t, "arn:aws:ecs:us-east-1:123456789012:cluster/agent-cluster", got.Cluster)
	assert.Equal(t, "arn:aws:ecs:us-east-1:123456789012:task/agent-cluster/abc123", got.TaskARN)
	assert.Equal(t, "anchore-ecs-inventory", got.Family)
	assert.Equal(t, "anchore-ecs-inventory-service", got.ServiceName)
	assert.Equal(t, "7", got.Revision)
}

func TestGetTaskMetadataFallsBackToV3EnvVar(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(taskMetadataFixture))
	}))
	defer server.Close()

	t.Setenv(metadataURIEnvVarV4, "")
	t.Setenv(metadataURIEnvVar, server.URL)

	got := GetTaskMetadata(context.Background())

	assert.Equal(t, "anchore-ecs-inventory", got.Family)
}

func TestGetTaskMetadataNotRunningInECS(t *testing.T) {
	t.Setenv(metadataURIEnvVarV4, "")
	t.Setenv(metadataURIEnvVar, "")

	got := GetTaskMetadata(context.Background())

	assert.Equal(t, TaskMetadata{}, got)
}

func TestGetTaskMetadataFailuresAreNotFatal(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
		{
			name: "unparsable body",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("not json"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			t.Setenv(metadataURIEnvVarV4, server.URL)

			assert.Equal(t, TaskMetadata{}, GetTaskMetadata(context.Background()))
		})
	}
}

func TestGetTaskMetadataUnreachableEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close() // nothing is listening any more

	t.Setenv(metadataURIEnvVarV4, url)

	assert.Equal(t, TaskMetadata{}, GetTaskMetadata(context.Background()))
}
