package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/h2non/gock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/ecs-inventory/internal/anchore"
	"github.com/anchore/ecs-inventory/internal/config"
	"github.com/anchore/ecs-inventory/internal/logger"
	"github.com/anchore/ecs-inventory/pkg/connection"
)

func init() {
	logger.Log = &logger.NoOpLogger{}
}

var (
	fixedNow  = time.Date(2024, time.April, 10, 12, 14, 16, 0, time.UTC)
	fixedUUID = uuid.MustParse("11111111-2222-3333-4444-555555555555")
)

func testNow() time.Time { return fixedNow }

func testUUID() uuid.UUID { return fixedUUID }

var testAnchoreDetails = connection.AnchoreInfo{
	URL:      "https://ancho.re",
	User:     "admin",
	Password: "foobar",
	Account:  "test-account",
	HTTP: connection.HTTPConfig{
		TimeoutSeconds: 10,
		Insecure:       true,
	},
}

func testConfig() *config.AppConfig {
	return &config.AppConfig{
		AnchoreDetails:              testAnchoreDetails,
		Region:                      "us-east-1",
		HealthReportIntervalSeconds: 60,
		PollingIntervalSeconds:      300,
	}
}

func TestGetRegistrationInfo(t *testing.T) {
	taskARN := "arn:aws:ecs:us-east-1:123456789012:task/agent-cluster/abc123"

	tests := []struct {
		name                       string
		registration               config.RegistrationOptions
		metadata                   TaskMetadata
		wantRegistrationID         string
		wantRegistrationInstanceID string
		wantName                   string
		wantClusterName            string
	}{
		{
			name: "config beats task metadata",
			registration: config.RegistrationOptions{
				RegistrationID:         "configured-id",
				RegistrationInstanceID: "configured-instance-id",
				IntegrationName:        "configured-name",
			},
			metadata: TaskMetadata{
				Cluster:     "agent-cluster",
				TaskARN:     taskARN,
				Family:      "metadata-family",
				ServiceName: "metadata-service",
			},
			wantRegistrationID:         "configured-id",
			wantRegistrationInstanceID: "configured-instance-id",
			wantName:                   "configured-name",
			wantClusterName:            "agent-cluster",
		},
		{
			// derived ids are qualified with the agent's own AWS account, cluster and
			// region: the family and service name alone are operator-chosen and repeat
			// across deployments
			name:         "task metadata beats generated",
			registration: config.RegistrationOptions{},
			metadata: TaskMetadata{
				Cluster:     "agent-cluster",
				TaskARN:     taskARN,
				Family:      "metadata-family",
				ServiceName: "metadata-service",
			},
			wantRegistrationID:         "metadata-family/123456789012/agent-cluster/us-east-1",
			wantRegistrationInstanceID: "metadata-service/123456789012/agent-cluster/us-east-1",
			wantName:                   "metadata-family",
			wantClusterName:            "agent-cluster",
		},
		{
			// a task started with RunTask rather than by a service has no service name,
			// so the family carries the instance id too
			name:         "task family used when the task belongs to no service",
			registration: config.RegistrationOptions{},
			metadata: TaskMetadata{
				Cluster: "agent-cluster",
				TaskARN: taskARN,
				Family:  "metadata-family",
			},
			wantRegistrationID:         "metadata-family/123456789012/agent-cluster/us-east-1",
			wantRegistrationInstanceID: "metadata-family/123456789012/agent-cluster/us-east-1",
			wantName:                   "metadata-family",
			wantClusterName:            "agent-cluster",
		},
		{
			// an agent outside ECS has no task metadata, so only the region is left to
			// qualify the derived instance id with
			name:         "derived ids drop the parts of the scope that are unavailable",
			registration: config.RegistrationOptions{},
			metadata:     TaskMetadata{Family: "metadata-family"},
			// the configured registration id wins over the derived one below; here
			// nothing but the family is available
			wantRegistrationID:         "metadata-family/us-east-1",
			wantRegistrationInstanceID: "metadata-family/us-east-1",
			wantName:                   "metadata-family",
			wantClusterName:            "",
		},
		{
			// configured ids are taken exactly as given: an operator who sets them owns
			// making them unique
			name: "configured instance id is not scoped",
			registration: config.RegistrationOptions{
				RegistrationInstanceID: "configured-instance-id",
			},
			metadata: TaskMetadata{
				Cluster:     "agent-cluster",
				Family:      "metadata-family",
				ServiceName: "metadata-service",
			},
			wantRegistrationID:         "metadata-family/agent-cluster/us-east-1",
			wantRegistrationInstanceID: "configured-instance-id",
			wantName:                   "metadata-family",
			wantClusterName:            "agent-cluster",
		},
		{
			name:                       "generated when nothing else is available",
			registration:               config.RegistrationOptions{},
			metadata:                   TaskMetadata{},
			wantRegistrationID:         fixedUUID.String(),
			wantRegistrationInstanceID: hostname(), // falls back to hostname before generating
			wantName:                   "",
			wantClusterName:            "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Registration = tt.registration

			got := getRegistrationInfo(cfg, tt.metadata, testUUID, testNow)

			assert.Equal(t, tt.wantRegistrationID, got.RegistrationID)
			assert.Equal(t, tt.wantRegistrationInstanceID, got.RegistrationInstanceID)
			assert.Equal(t, tt.wantName, got.Name)
			assert.Equal(t, tt.wantClusterName, got.ClusterName)

			assert.Equal(t, Type, got.Type)
			assert.Equal(t, "admin", got.Username)
			assert.Equal(t, "test-account", got.AccountName)
			assert.Equal(t, []string{"test-account"}, got.ExplicitlyAccountBound)
			assert.Equal(t, 60, got.HealthReportInterval)
			assert.Equal(t, fixedNow, got.StartedAt.Time)
			assert.Equal(t, devVersion, got.Version)
			// never send the app config, it carries AWS region/credential-shaped material
			assert.Nil(t, got.Configuration)
			// Kubernetes-only fields stay empty for ECS
			assert.Empty(t, got.Namespace)
			assert.Empty(t, got.Namespaces)
		})
	}
}

// Enterprise creates a new integration record for every unseen
// (registration_id, registration_instance_id) pair and only ever marks the old ones
// INACTIVE, so neither half may contain the task id: ECS mints a new one on every task
// replacement.
func TestGetRegistrationInfoNeverIdentifiesTheAgentByTaskARN(t *testing.T) {
	metadata := TaskMetadata{
		Cluster:     "agent-cluster",
		TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/agent-cluster/abc123",
		Family:      "metadata-family",
		ServiceName: "metadata-service",
	}

	first := getRegistrationInfo(testConfig(), metadata, testUUID, testNow)

	// same agent, restarted: everything about the task is the same bar its id
	restarted := metadata
	restarted.TaskARN = "arn:aws:ecs:us-east-1:123456789012:task/agent-cluster/def456"
	second := getRegistrationInfo(testConfig(), restarted, testUUID, testNow)

	assert.Equal(t, first.RegistrationID, second.RegistrationID)
	assert.Equal(t, first.RegistrationInstanceID, second.RegistrationInstanceID)
	assert.NotContains(t, first.RegistrationInstanceID, "abc123")
}

// The other half of the same constraint: Enterprise keys an integration on the pair and
// does not qualify it by region or Anchore account, so two agents deployed from one task
// definition into different regions or AWS accounts must not derive the same pair. If
// they did they would share a single integration record — the healthy one clearing the
// broken one's UNHEALTHY state, or one of the two 404ing on every health report.
func TestGetRegistrationInfoDistinguishesAgentsDeployedFromTheSameTaskDefinition(t *testing.T) {
	// same task definition, same service name, deployed twice
	sameTaskDefinition := TaskMetadata{Family: "anchore-ecs-inventory", ServiceName: "anchore-ecs-inventory"}

	pair := func(cfg *config.AppConfig, metadata TaskMetadata) [2]string {
		info := getRegistrationInfo(cfg, metadata, testUUID, testNow)
		return [2]string{info.RegistrationID, info.RegistrationInstanceID}
	}

	usEast := testConfig()
	usEast.Region = "us-east-1"
	euWest := testConfig()
	euWest.Region = "eu-west-1"

	// two regions, one AWS account
	assert.NotEqual(t,
		pair(usEast, withCluster(sameTaskDefinition, "arn:aws:ecs:us-east-1:123456789012:cluster/agents")),
		pair(euWest, withCluster(sameTaskDefinition, "arn:aws:ecs:eu-west-1:123456789012:cluster/agents")),
		"agents in different regions must not share a registration pair")

	// two AWS accounts, one region — the region cannot tell these apart, the cluster can
	assert.NotEqual(t,
		pair(usEast, withCluster(sameTaskDefinition, "arn:aws:ecs:us-east-1:123456789012:cluster/agents")),
		pair(usEast, withCluster(sameTaskDefinition, "arn:aws:ecs:us-east-1:210987654321:cluster/agents")),
		"agents in different AWS accounts must not share a registration pair")

	// two AWS accounts, one region, and an ECS agent that reports the cluster as a bare
	// name rather than an ARN — the cluster then carries no account of its own, so only
	// the account id in the task ARN keeps the two apart
	shortClusterName := withCluster(sameTaskDefinition, "agents")
	assert.NotEqual(t,
		pair(usEast, withTaskARN(shortClusterName, "arn:aws:ecs:us-east-1:123456789012:task/agents/abc123")),
		pair(usEast, withTaskARN(shortClusterName, "arn:aws:ecs:us-east-1:210987654321:task/agents/def456")),
		"agents in different AWS accounts must not share a registration pair when the cluster is a bare name")

	// two clusters in one account and region, e.g. an agent per environment
	assert.NotEqual(t,
		pair(usEast, withCluster(sameTaskDefinition, "prod")),
		pair(usEast, withCluster(sameTaskDefinition, "staging")),
		"agents in different clusters must not share a registration pair")

	// and the scoping must not have cost the stability the pair also needs
	assert.Equal(t,
		pair(usEast, withCluster(sameTaskDefinition, "prod")),
		pair(usEast, withCluster(sameTaskDefinition, "prod")),
		"the same agent must derive the same registration pair on every start")
}

func withCluster(metadata TaskMetadata, cluster string) TaskMetadata {
	metadata.Cluster = cluster
	return metadata
}

func withTaskARN(metadata TaskMetadata, taskARN string) TaskMetadata {
	metadata.TaskARN = taskARN
	return metadata
}

func TestAWSAccountID(t *testing.T) {
	tests := []struct {
		name    string
		taskARN string
		want    string
	}{
		{
			name:    "current task arn",
			taskARN: "arn:aws:ecs:us-east-1:123456789012:task/agent-cluster/abc123",
			want:    "123456789012",
		},
		{
			name:    "pre-2016 task arn without the cluster segment",
			taskARN: "arn:aws:ecs:us-east-1:123456789012:task/abc123",
			want:    "123456789012",
		},
		{
			name:    "non-commercial partition",
			taskARN: "arn:aws-us-gov:ecs:us-gov-west-1:123456789012:task/agent-cluster/abc123",
			want:    "123456789012",
		},
		{
			name:    "no task metadata at all",
			taskARN: "",
			want:    "",
		},
		{
			name:    "not an arn",
			taskARN: "agent-cluster/abc123",
			want:    "",
		},
		{
			name:    "truncated arn",
			taskARN: "arn:aws:ecs:us-east-1:123456789012",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, awsAccountID(tt.taskARN))
		})
	}
}

func TestGetRegistrationInfoDescriptionFromConfig(t *testing.T) {
	cfg := testConfig()
	cfg.Registration = config.RegistrationOptions{IntegrationDescription: "the ecs agent"}

	got := getRegistrationInfo(cfg, TaskMetadata{}, testUUID, testNow)

	assert.Equal(t, "the ecs agent", got.Description)
}

func TestRegistrationMarshalsKubernetesFieldsAway(t *testing.T) {
	got := getRegistrationInfo(testConfig(), TaskMetadata{Family: "fam", TaskARN: "task"}, testUUID, testNow)
	got.Uptime = nil

	body, err := json.Marshal(got)
	require.NoError(t, err)

	assert.Contains(t, string(body), `"type":"ecs_inventory_agent"`)
	assert.NotContains(t, string(body), "namespace")
	assert.NotContains(t, string(body), "configuration")
}

func TestDoRegister(t *testing.T) {
	defer gock.Off()

	var sentBody map[string]interface{}
	gock.New("https://ancho.re").
		Post("/v2/system/integrations/registration").
		MatchHeader("x-anchore-account", "test-account").
		BasicAuth("admin", "foobar").
		AddMatcher(func(req *http.Request, _ *gock.Request) (bool, error) {
			return true, json.NewDecoder(req.Body).Decode(&sentBody)
		}).
		Reply(200).
		JSON(map[string]interface{}{
			"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			"type": "ecs_inventory_agent",
			"name": "fam",
		})

	registrationInfo := getRegistrationInfo(testConfig(), TaskMetadata{Family: "fam", TaskARN: "task"}, testUUID, testNow)

	registered, err := doRegister(registrationInfo, testAnchoreDetails, testNow)

	require.NoError(t, err)
	assert.True(t, gock.IsDone())
	assert.Equal(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", registered.UUID)
	assert.Equal(t, "ecs_inventory_agent", sentBody["type"])
	assert.Equal(t, "fam/us-east-1", sentBody["registration_id"])
}

func TestRegisterReturnsUnsupportedOnBadRequest(t *testing.T) {
	defer gock.Off()
	gock.New("https://ancho.re").
		Post("/v2/system/integrations/registration").
		Reply(400).
		JSON(map[string]interface{}{
			"message":  "value is not a valid enumeration member; permitted: 'k8s_inventory_agent'",
			"detail":   map[string]interface{}{},
			"httpcode": 400,
		})

	registrationInfo := getRegistrationInfo(testConfig(), TaskMetadata{Family: "fam"}, testUUID, testNow)

	registered, err := register(registrationInfo, testAnchoreDetails, 0, time.Millisecond, time.Millisecond, testNow)

	assert.Nil(t, registered)
	assert.ErrorIs(t, err, ErrRegistrationUnsupported)
}

func TestRegisterReturnsUnsupportedWhenEndpointMissing(t *testing.T) {
	defer gock.Off()
	gock.New("https://ancho.re").
		Post("/v2/system/integrations/registration").
		Reply(404).
		JSON(map[string]interface{}{
			"type":   "about:blank",
			"title":  "Not Found",
			"detail": "The requested URL was not found on the server.",
			"status": 404,
		})

	registrationInfo := getRegistrationInfo(testConfig(), TaskMetadata{Family: "fam"}, testUUID, testNow)

	_, err := register(registrationInfo, testAnchoreDetails, 0, time.Millisecond, time.Millisecond, testNow)

	assert.ErrorIs(t, err, ErrRegistrationUnsupported)
}

func TestRegisterBailsOnBadCredentials(t *testing.T) {
	defer gock.Off()
	gock.New("https://ancho.re").
		Post("/v2/system/integrations/registration").
		Reply(401).
		JSON(map[string]interface{}{"message": "Unauthorized", "detail": map[string]interface{}{}, "httpcode": 401})

	registrationInfo := getRegistrationInfo(testConfig(), TaskMetadata{Family: "fam"}, testUUID, testNow)

	_, err := register(registrationInfo, testAnchoreDetails, 0, time.Millisecond, time.Millisecond, testNow)

	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrRegistrationUnsupported)
	assert.True(t, anchore.IncorrectCredentials(err))
}

func TestRegisterBailsOnMissingPrivileges(t *testing.T) {
	defer gock.Off()
	gock.New("https://ancho.re").
		Post("/v2/system/integrations/registration").
		Reply(403).
		JSON(map[string]interface{}{
			"message":  "Not authorized. Requires permissions: domain=test-account action=reportHealth",
			"detail":   map[string]interface{}{},
			"httpcode": 403,
		})

	registrationInfo := getRegistrationInfo(testConfig(), TaskMetadata{Family: "fam"}, testUUID, testNow)

	_, err := register(registrationInfo, testAnchoreDetails, 0, time.Millisecond, time.Millisecond, testNow)

	require.Error(t, err)
	assert.True(t, anchore.UserLacksAPIPrivileges(err))
}

func TestAwaitVersion(t *testing.T) {
	tests := []struct {
		name           string
		serviceVersion string
		wantSupported  bool
	}{
		{name: "required version", serviceVersion: "6.2.0", wantSupported: true},
		{name: "newer prerelease", serviceVersion: "6.3.0-alpha.1", wantSupported: true},
		{name: "newer release", serviceVersion: "7.0.0", wantSupported: true},
		{name: "too old", serviceVersion: "6.1.0", wantSupported: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer gock.Off()
			gock.New("https://ancho.re").
				Get("/version").
				Persist().
				Reply(200).
				JSON(map[string]interface{}{
					"api":     map[string]string{"version": "2"},
					"db":      map[string]string{"schema_version": tt.serviceVersion},
					"service": map[string]string{"version": tt.serviceVersion},
				})

			got, err := awaitVersion(testAnchoreDetails, 0, time.Millisecond, time.Millisecond)

			if tt.wantSupported {
				require.NoError(t, err)
				assert.Equal(t, tt.serviceVersion, got.Service.Version)
			} else {
				// too old: it keeps retrying in case Enterprise is upgraded, so with
				// maxRetry 0 it gives up with an error
				assert.Error(t, err)
			}
		})
	}
}

func TestAwaitVersionRetriesWhileOffline(t *testing.T) {
	defer gock.Off()
	gock.New("https://ancho.re").
		Get("/version").
		Persist().
		Reply(503).
		JSON(map[string]interface{}{"message": "unavailable", "detail": map[string]interface{}{}, "httpcode": 503})

	_, err := awaitVersion(testAnchoreDetails, 2, time.Millisecond, time.Millisecond)

	assert.ErrorContains(t, err, "failed to get Enterprise version after 3 attempts")
}

func TestGetChannels(t *testing.T) {
	ch := GetChannels()

	assert.Equal(t, 1, cap(ch.HealthReportingEnabled), "must be buffered so registration does not block")
	assert.Equal(t, 0, cap(ch.IntegrationObj))
	assert.Equal(t, 1, cap(ch.InventoryReportingEnabled),
		"must be buffered so enabling inventory reporting never waits for the inventory loop")
}

func TestRegistrationIsUnsupported(t *testing.T) {
	assert.True(t, registrationIsUnsupported(&anchore.APIClientError{HTTPStatusCode: http.StatusBadRequest}))
	assert.True(t, registrationIsUnsupported(&anchore.APIClientError{
		HTTPStatusCode:         http.StatusMethodNotAllowed,
		ControllerErrorDetails: &anchore.ControllerErrorDetails{Detail: "Method Not Allowed"},
	}))
	assert.False(t, registrationIsUnsupported(&anchore.APIClientError{HTTPStatusCode: http.StatusForbidden}))
	assert.False(t, registrationIsUnsupported(nil))
}

// Whatever happens during registration, inventory reporting must start: it is the
// agent's primary job and does not depend on Enterprise supporting health reporting.
func TestPerformRegistrationAlwaysEnablesInventoryReporting(t *testing.T) {
	tests := []struct {
		name        string
		registerRep func(g *gock.Request) *gock.Response
		wantErr     bool
	}{
		{
			name: "registration succeeds",
			registerRep: func(g *gock.Request) *gock.Response {
				return g.Reply(200).JSON(map[string]interface{}{"uuid": "aaaa-bbbb"})
			},
			wantErr: false,
		},
		{
			name: "enterprise rejects the ecs agent type",
			registerRep: func(g *gock.Request) *gock.Response {
				return g.Reply(400).JSON(map[string]interface{}{
					"message": "not a valid enumeration member", "detail": map[string]interface{}{}, "httpcode": 400,
				})
			},
			wantErr: true,
		},
		{
			name: "user lacks the reportHealth permission",
			registerRep: func(g *gock.Request) *gock.Response {
				return g.Reply(403).JSON(map[string]interface{}{
					"message": "Not authorized. Requires permissions: action=reportHealth",
					"detail":  map[string]interface{}{}, "httpcode": 403,
				})
			},
			wantErr: true,
		},
		{
			name: "credentials are wrong",
			registerRep: func(g *gock.Request) *gock.Response {
				return g.Reply(401).JSON(map[string]interface{}{
					"message": "Unauthorized", "detail": map[string]interface{}{}, "httpcode": 401,
				})
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer gock.Off()

			gock.New("https://ancho.re").
				Get("/version").
				Reply(200).
				JSON(map[string]interface{}{
					"api":     map[string]string{"version": "2"},
					"db":      map[string]string{"schema_version": "6.2.0"},
					"service": map[string]string{"version": "6.2.0"},
				})
			tt.registerRep(gock.New("https://ancho.re").Post("/v2/system/integrations/registration"))

			ch := GetChannels()

			// stand in for the health reporting goroutine, which must not deadlock registration
			go func() {
				for range ch.IntegrationObj { //nolint:revive // draining the channel is the point
				}
			}()

			inventoryEnabled := make(chan bool, 1)
			go func() {
				enabled, ok := <-ch.InventoryReportingEnabled
				inventoryEnabled <- ok && enabled
			}()

			_, err := PerformRegistration(testConfig(), ch)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			select {
			case enabled := <-inventoryEnabled:
				assert.True(t, enabled, "inventory reporting must be enabled regardless of registration outcome")
			case <-time.After(2 * time.Second):
				t.Fatal("inventory reporting was never enabled")
			}
		})
	}
}

// Inventory reporting must start while registration is still retrying an unreachable
// Enterprise, not once it has given up: the retry loops back off to an hour, and the
// agent gathering no inventory for that long would be a regression on the behaviour
// before health reporting existed.
func TestPerformRegistrationEnablesInventoryReportingWhileEnterpriseIsOffline(t *testing.T) {
	tests := []struct {
		name  string
		setup func()
	}{
		{
			name: "version probe cannot reach enterprise",
			setup: func() {
				gock.New("https://ancho.re").
					Get("/version").
					Persist().
					ReplyError(fmt.Errorf("dial tcp 127.0.0.1:8228: connect: %w", syscall.ECONNREFUSED))
			},
		},
		{
			name: "enterprise goes away between the version probe and registration",
			setup: func() {
				gock.New("https://ancho.re").
					Get("/version").
					Persist().
					Reply(200).
					JSON(map[string]interface{}{
						"api":     map[string]string{"version": "2"},
						"db":      map[string]string{"schema_version": "6.2.0"},
						"service": map[string]string{"version": "6.2.0"},
					})
				gock.New("https://ancho.re").
					Post("/v2/system/integrations/registration").
					Persist().
					ReplyError(fmt.Errorf("dial tcp 127.0.0.1:8228: connect: %w", syscall.ECONNREFUSED))
			},
		},
		{
			name: "enterprise is too old to register an ecs agent",
			setup: func() {
				gock.New("https://ancho.re").
					Get("/version").
					Persist().
					Reply(200).
					JSON(map[string]interface{}{
						"api":     map[string]string{"version": "2"},
						"db":      map[string]string{"schema_version": "6.1.0"},
						"service": map[string]string{"version": "6.1.0"},
					})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer gock.Off()
			tt.setup()

			ch := GetChannels()
			go func() {
				for range ch.IntegrationObj { //nolint:revive // draining the channel is the point
				}
			}()

			// ~1s of retrying, asserted against a 250ms deadline below: enabling inventory
			// reporting only once registration gives up (the previous behaviour) misses
			// that deadline by a wide margin, so this test fails if the defer creeps back.
			policy := retryPolicy{
				maxRetry:             100,
				versionStartBackoff:  10 * time.Millisecond,
				versionMaxBackoff:    10 * time.Millisecond,
				registerStartBackoff: 10 * time.Millisecond,
				registerMaxBackoff:   10 * time.Millisecond,
			}

			done := make(chan struct{})
			go func() {
				defer close(done)
				_, err := performRegistration(testConfig(), ch, policy)
				assert.Error(t, err)
			}()

			select {
			case enabled, ok := <-ch.InventoryReportingEnabled:
				assert.True(t, ok && enabled, "inventory reporting must be enabled before registration is retried")
			case <-time.After(250 * time.Millisecond):
				t.Fatal("inventory reporting was never enabled while Enterprise was unreachable")
			}

			<-done
		})
	}
}
