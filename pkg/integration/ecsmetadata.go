package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/anchore/ecs-inventory/internal/logger"
)

// The ECS agent injects one of these into every task it runs. Their absence means
// the agent is not running as an ECS task (e.g. local or plain docker), which is a
// supported way to run it.
const (
	metadataURIEnvVarV4 = "ECS_CONTAINER_METADATA_URI_V4"
	metadataURIEnvVar   = "ECS_CONTAINER_METADATA_URI"
)

// The metadata endpoint is a link-local address on the task's own host, so it either
// answers promptly or is not there at all. Registration should not stall on it.
const metadataTimeout = 2 * time.Second

// TaskMetadata is the subset of the ECS task metadata endpoint v4 response that is
// used to derive this agent's registration identity.
//
// See https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint-v4.html
type TaskMetadata struct {
	Cluster string `json:"Cluster"`
	TaskARN string `json:"TaskARN"`
	Family  string `json:"Family"`
	// ServiceName is only present for tasks launched by an ECS service. Unlike
	// TaskARN it survives task replacement, which is what makes it usable as a
	// registration identity.
	ServiceName string `json:"ServiceName"`
	Revision    string `json:"Revision"`
}

// GetTaskMetadata returns the metadata for the ECS task this agent runs in, or a zero
// value if the agent is not running as an ECS task. Failures are never fatal: the
// registration identity simply falls back to config values and generated ones.
func GetTaskMetadata(ctx context.Context) TaskMetadata {
	baseURI := os.Getenv(metadataURIEnvVarV4)
	if baseURI == "" {
		baseURI = os.Getenv(metadataURIEnvVar)
	}
	if baseURI == "" {
		logger.Log.Debug("No ECS task metadata endpoint in the environment, not running as an ECS task")
		return TaskMetadata{}
	}

	metadata, err := fetchTaskMetadata(ctx, baseURI)
	if err != nil {
		logger.Log.Warn("Failed to read ECS task metadata, falling back to configured/generated registration values",
			"err", err)
		return TaskMetadata{}
	}

	logger.Log.Debug("Determined ECS task metadata",
		"cluster", metadata.Cluster, "taskARN", metadata.TaskARN, "family", metadata.Family,
		"serviceName", metadata.ServiceName)
	return metadata
}

func fetchTaskMetadata(ctx context.Context, baseURI string) (TaskMetadata, error) {
	ctx, cancel := context.WithTimeout(ctx, metadataTimeout)
	defer cancel()

	endpoint, err := taskMetadataURL(baseURI)
	if err != nil {
		return TaskMetadata{}, err
	}

	// #nosec G704 -- the endpoint comes from the environment by design (the ECS agent
	// injects it), and taskMetadataURL constrains it to a plain http URL
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return TaskMetadata{}, fmt.Errorf("failed to build ECS task metadata request: %w", err)
	}

	client := &http.Client{Timeout: metadataTimeout}
	// #nosec G704 -- see above
	response, err := client.Do(request)
	if err != nil {
		return TaskMetadata{}, fmt.Errorf("failed to query ECS task metadata: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return TaskMetadata{}, fmt.Errorf("unexpected status %s from ECS task metadata endpoint", response.Status)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return TaskMetadata{}, fmt.Errorf("failed to read ECS task metadata response: %w", err)
	}

	metadata := TaskMetadata{}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return TaskMetadata{}, fmt.Errorf("failed to parse ECS task metadata response: %w", err)
	}
	return metadata, nil
}

// taskMetadataURL builds the /task URL, rejecting anything that is not a plain http
// endpoint. The base comes from the environment, so it is worth being narrow about
// what the agent will talk to.
func taskMetadataURL(baseURI string) (string, error) {
	parsed, err := url.Parse(baseURI)
	if err != nil {
		return "", fmt.Errorf("invalid ECS task metadata endpoint %q: %w", baseURI, err)
	}
	if parsed.Scheme != "http" || parsed.Host == "" {
		return "", fmt.Errorf("unsupported ECS task metadata endpoint %q, expected a http url", baseURI)
	}
	return parsed.JoinPath("task").String(), nil
}
