// Package integration registers anchore-ecs-inventory with Anchore Enterprise as an
// integration instance, which is what allows Enterprise to track the agent's health.
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/go-version"

	"github.com/anchore/ecs-inventory/internal/anchore"
	"github.com/anchore/ecs-inventory/internal/config"
	"github.com/anchore/ecs-inventory/internal/logger"
	jstime "github.com/anchore/ecs-inventory/internal/time"
	aeiVersion "github.com/anchore/ecs-inventory/internal/version"
	"github.com/anchore/ecs-inventory/pkg/connection"
)

// The Enterprise release that first understands the ecs_inventory_agent integration
// type: 6.2.0 is the version the Enterprise-side support is landing in, and no 6.2.x has
// been released without it. Older deployments reject registration, which the agent
// degrades around rather than failing on (see ErrRegistrationUnsupported).
//
// The check is a courtesy, not a guarantee — pre-release builds carry the version string
// of the release they are heading for, so a 6.2.0 development build from before the
// Enterprise change passes this gate and then 400s the registration. That path is handled
// (registrationIsUnsupported), so a wrong-in-this-direction gate degrades gracefully,
// whereas setting it too high would silently disable health reporting against an
// Enterprise that supports it. If the Enterprise change slips past 6.2.0, bump this to the
// release that actually ships it.
var requiredAnchoreVersion, _ = version.NewVersion("6.2.0")

const Type = "ecs_inventory_agent"
const RegisterAPIPathV2 = "v2/system/integrations/registration"
const devVersion = "dev"

// ErrRegistrationUnsupported is returned when Anchore Enterprise is reachable and the
// credentials are good, but the deployment does not support registering an ECS
// inventory agent. Inventory reporting continues; health reporting does not.
var ErrRegistrationUnsupported = errors.New("anchore enterprise does not support ecs inventory agent registration")

type Channels struct {
	IntegrationObj            chan *Integration
	HealthReportingEnabled    chan bool
	InventoryReportingEnabled chan bool
}

// HealthStatus reflects the state of the Integration wrt any errors
// encountered when performing its tasks
type HealthStatus struct {
	State   string `json:"state,omitempty"` // state of the integration HEALTHY or UNHEALTHY
	Reason  string `json:"reason,omitempty"`
	Details any    `json:"details,omitempty"`
}

// LifeCycleStatus reflects the state of the Integration from the perspective of Enterprise
type LifeCycleStatus struct {
	State     string          `json:"state,omitempty"` // lifecycle state REGISTERED, ACTIVE, DEGRADED, DEACTIVATED
	Reason    string          `json:"reason,omitempty"`
	Details   any             `json:"details,omitempty"`
	UpdatedAt jstime.Datetime `json:"updated_at,omitempty"`
}

type Integration struct {
	UUID                   string                 `json:"uuid,omitempty"`                     // uuid provided to this integration instance during registration
	Type                   string                 `json:"type,omitempty"`                     // type of integration (i.e. 'ecs_inventory_agent')
	Name                   string                 `json:"name,omitempty"`                     // name of the integration instance
	Description            string                 `json:"description,omitempty"`              // short description of integration instance
	Version                string                 `json:"version,omitempty"`                  // version of the integration instance
	ReportedStatus         *HealthStatus          `json:"reported_status,omitempty"`          // health status of the integration (Read-only)
	IntegrationStatus      *LifeCycleStatus       `json:"integration_status,omitempty"`       // lifecycle status of the integration (Read-only)
	StartedAt              jstime.Datetime        `json:"started_at,omitempty"`               // timestamp when integration instance was started in UTC().Format(time.RFC3339)
	LastSeen               *jstime.Datetime       `json:"last_seen,omitempty"`                // timestamp of last received health report from integration instance (Read-only)
	Uptime                 *jstime.Duration       `json:"uptime,omitempty"`                   // running time of integration instance
	Username               string                 `json:"username,omitempty"`                 // user that the integration instance authenticates as during registration
	AccountName            string                 `json:"account_name,omitempty"`             // default account that the integration instance authenticates as during registration
	ExplicitlyAccountBound []string               `json:"explicitly_account_bound,omitempty"` // accounts that the integration instance is explicitly configured to handle
	Accounts               []string               `json:"accounts,omitempty"`                 // names of accounts that the integration instance handled recently
	Namespaces             []string               `json:"namespaces,omitempty"`               // namespaces that the integration instance handles (Kubernetes only)
	Configuration          map[string]interface{} `json:"configuration,omitempty"`            // configuration for the integration instance
	ClusterName            string                 `json:"cluster_name,omitempty"`             // name of the cluster the integration instance itself runs in
	Namespace              string                 `json:"namespace,omitempty"`                // namespace that the integration instance belongs to (Kubernetes only)
	HealthReportInterval   int                    `json:"health_report_interval,omitempty"`   // time in seconds between health reports
	RegistrationID         string                 `json:"registration_id,omitempty"`          // id that the integration used during registration
	RegistrationInstanceID string                 `json:"registration_instance_id,omitempty"` // instance id used by the integration during registration
}

type Registration struct {
	RegistrationID         string           `json:"registration_id,omitempty"`          // id that identifies the integration during registration
	RegistrationInstanceID string           `json:"registration_instance_id,omitempty"` // identifier that makes an integration instance unique among its replicas
	Type                   string           `json:"type,omitempty"`                     // type of integration (i.e. 'ecs_inventory_agent')
	Name                   string           `json:"name,omitempty"`                     // name of the integration instance
	Description            string           `json:"description,omitempty"`              // short description of integration instance
	Version                string           `json:"version,omitempty"`                  // version of the integration instance
	StartedAt              jstime.Datetime  `json:"started_at,omitempty"`               // timestamp when integration instance was started in UTC().Format(time.RFC3339)
	Uptime                 *jstime.Duration `json:"uptime,omitempty"`                   // running time of integration instance
	Username               string           `json:"username,omitempty"`                 // user that the integration instance authenticates as during registration
	AccountName            string           `json:"account_name,omitempty"`             // default account that the integration instance reports into
	ExplicitlyAccountBound []string         `json:"explicitly_account_bound,omitempty"` // accounts that the integration instance is explicitly configured to handle
	Namespaces             []string         `json:"namespaces,omitempty"`               // namespaces that the integration instance handles (Kubernetes only)
	Configuration          map[string]any   `json:"configuration,omitempty"`            // configuration for the integration instance
	ClusterName            string           `json:"cluster_name,omitempty"`             // name of the ECS cluster the integration instance itself runs in
	Namespace              string           `json:"namespace,omitempty"`                // namespace that the integration instance belongs to (Kubernetes only)
	HealthReportInterval   int              `json:"health_report_interval,omitempty"`   // time in seconds between health reports
}

type _NewUUID func() uuid.UUID

type _Now func() time.Time

// retryPolicy bounds the version probe and registration retry loops. A negative
// maxRetry retries indefinitely, which is what the agent does in production; tests
// supply their own policy to keep the loops short.
type retryPolicy struct {
	maxRetry             int
	versionStartBackoff  time.Duration
	versionMaxBackoff    time.Duration
	registerStartBackoff time.Duration
	registerMaxBackoff   time.Duration
}

var defaultRetryPolicy = retryPolicy{
	maxRetry:             -1,
	versionStartBackoff:  2 * time.Second,
	versionMaxBackoff:    1 * time.Hour,
	registerStartBackoff: 2 * time.Second,
	registerMaxBackoff:   10 * time.Minute,
}

// PerformRegistration registers this agent with Anchore Enterprise and, on success,
// signals the health reporting goroutine to start.
//
// It retries an unreachable Enterprise for as long as it takes, so it is expected to
// run on its own goroutine.
func PerformRegistration(appConfig *config.AppConfig, ch Channels) (*Integration, error) {
	return performRegistration(appConfig, ch, defaultRetryPolicy)
}

func performRegistration(appConfig *config.AppConfig, ch Channels, policy retryPolicy) (*Integration, error) {
	defer closeChannels(ch)

	// Inventory reporting is this agent's primary job and does not depend on
	// registration at all, so it starts up front rather than once registration has
	// resolved: both awaitVersion and register retry an offline Enterprise
	// indefinitely, and inventory must not be starved for however long that takes.
	enableInventoryReporting(ch)

	if _, err := awaitVersion(appConfig.AnchoreDetails, policy.maxRetry,
		policy.versionStartBackoff, policy.versionMaxBackoff); err != nil {
		return nil, err
	}

	metadata := GetTaskMetadata(context.Background())
	registrationInfo := getRegistrationInfo(appConfig, metadata, uuid.New, time.Now)

	registeredIntegration, err := register(registrationInfo, appConfig.AnchoreDetails, policy.maxRetry,
		policy.registerStartBackoff, policy.registerMaxBackoff, time.Now)
	if err != nil {
		return nil, err
	}

	enableHealthReporting(ch, registeredIntegration)

	return registeredIntegration, nil
}

func awaitVersion(anchoreDetails connection.AnchoreInfo, maxRetry int, startBackoff, maxBackoff time.Duration) (*anchore.Version, error) {
	attempt := 0
	loggedTooOld := false
	for {
		retry := false

		anchoreVersion, err := anchore.GetVersion(anchoreDetails)
		if err == nil {
			ver, vErr := version.NewVersion(anchoreVersion.Service.Version)
			switch {
			case vErr != nil:
				logger.Log.Error("Failed to parse received service version, will try again", vErr,
					"backoff", startBackoff.String())
				retry = true
			case ver.GreaterThanOrEqual(requiredAnchoreVersion):
				logger.Log.Info("Proceeding with integration registration",
					"enterpriseVersion", anchoreVersion.Service.Version, "url", anchoreDetails.URL)
				return anchoreVersion, nil
			default:
				// Inventory reporting is already running, so keep polling in case
				// Enterprise is upgraded under us, but say so only once.
				if !loggedTooOld {
					logger.Log.Info("Proceeding without integration registration and health reporting, Enterprise is too old to support it",
						"enterpriseVersion", anchoreVersion.Service.Version,
						"requiredVersion", requiredAnchoreVersion.String())
					loggedTooOld = true
				}
				retry = true
			}
		}

		attempt++
		if maxRetry >= 0 && attempt > maxRetry {
			logger.Log.Info("Failed to get Enterprise version", "attempts", attempt)
			return nil, fmt.Errorf("failed to get Enterprise version after %d attempts", attempt)
		}

		if anchore.ServerIsOffline(err) {
			logger.Log.Info("Anchore is offline, will try again", "backoff", startBackoff.String())
			retry = true
		}

		if retry {
			time.Sleep(startBackoff)
			if startBackoff < maxBackoff {
				startBackoff = min(startBackoff*2, maxBackoff)
			}
			continue
		}

		logger.Log.Error("Failed to get service version for Enterprise", err, "url", anchoreDetails.URL)
		return nil, err
	}
}

func GetChannels() Channels {
	return Channels{
		IntegrationObj:            make(chan *Integration),
		HealthReportingEnabled:    make(chan bool, 1), // buffered to prevent registration from blocking
		InventoryReportingEnabled: make(chan bool, 1), // buffered so enabling never waits for the inventory loop to start
	}
}

func closeChannels(ch Channels) {
	close(ch.IntegrationObj)
	close(ch.HealthReportingEnabled)
	close(ch.InventoryReportingEnabled)
}

func enableHealthReporting(ch Channels, integration *Integration) {
	logger.Log.Info("Activating health reporting")
	// signal health reporting to start by providing it with the integration
	ch.IntegrationObj <- integration
	// signal inventory reporting to populate health report info when generating inventory reports
	ch.HealthReportingEnabled <- true
}

func enableInventoryReporting(ch Channels) {
	logger.Log.Info("Activating inventory reporting")
	// signal inventory reporting to start
	ch.InventoryReportingEnabled <- true
}

// EnableInventoryReportingOnly starts inventory reporting without registering the
// agent with Enterprise. Used for dry runs, where registering a throwaway agent as a
// live integration would be wrong.
func EnableInventoryReportingOnly(ch Channels) {
	enableInventoryReporting(ch)
}

func register(registrationInfo *Registration, anchoreDetails connection.AnchoreInfo, maxRetry int,
	startBackoff, maxBackoff time.Duration, now _Now,
) (*Integration, error) {
	attempt := 0
	for {
		registeredIntegration, err := doRegister(registrationInfo, anchoreDetails, now)
		if err == nil {
			logger.Log.Info("Successfully registered agent with Anchore",
				"type", registrationInfo.Type, "name", registrationInfo.Name,
				"registrationID", registrationInfo.RegistrationID,
				"registrationInstanceID", registrationInfo.RegistrationInstanceID,
				"integrationUUID", registeredIntegration.UUID, "url", anchoreDetails.URL)
			return registeredIntegration, nil
		}

		// Terminal conditions first: retrying, or exhausting the retry budget, tells the
		// caller nothing it does not already know from the error itself.

		// An Enterprise that predates ECS agent support either has no such endpoint at
		// all, or rejects the ecs_inventory_agent integration type with a 400. Neither
		// should stop inventory reporting.
		if registrationIsUnsupported(err) {
			logger.Log.Warn("This Anchore Enterprise does not support ECS inventory agent registration, continuing without health reporting",
				"err", err.Error(), "requiredVersion", requiredAnchoreVersion.String())
			return nil, fmt.Errorf("%w: %w", ErrRegistrationUnsupported, err)
		}

		if anchore.UserLacksAPIPrivileges(err) {
			logger.Log.Error("Specified user lacks the privileges required to register and send health reports", err)
			return nil, err
		}

		if anchore.IncorrectCredentials(err) {
			logger.Log.Error("Failed to register due to invalid credentials (wrong username or password)", err)
			return nil, err
		}

		attempt++
		if maxRetry >= 0 && attempt > maxRetry {
			logger.Log.Error("Failed to register agent", err,
				"registrationID", registrationInfo.RegistrationID,
				"registrationInstanceID", registrationInfo.RegistrationInstanceID, "attempts", attempt)
			return nil, fmt.Errorf("failed to register after %d attempts: %w", attempt, err)
		}

		if anchore.ServerIsOffline(err) {
			logger.Log.Info("Anchore is offline, will try again", "backoff", startBackoff.String())
			time.Sleep(startBackoff)
			if startBackoff < maxBackoff {
				startBackoff = min(startBackoff*2, maxBackoff)
			}
			continue
		}

		logger.Log.Error("Failed to register integration agent", err,
			"registrationID", registrationInfo.RegistrationID,
			"registrationInstanceID", registrationInfo.RegistrationInstanceID)
		return nil, err
	}
}

func registrationIsUnsupported(err error) bool {
	if anchore.ServerLacksAgentHealthAPISupport(err) {
		return true
	}

	var apiClientError *anchore.APIClientError
	return errors.As(err, &apiClientError) && apiClientError.HTTPStatusCode == http.StatusBadRequest
}

func doRegister(registrationInfo *Registration, anchoreDetails connection.AnchoreInfo, now _Now) (*Integration, error) {
	logger.Log.Info("Registering agent with Anchore",
		"type", registrationInfo.Type, "name", registrationInfo.Name,
		"registrationID", registrationInfo.RegistrationID,
		"registrationInstanceID", registrationInfo.RegistrationInstanceID, "url", anchoreDetails.URL)

	registrationInfo.Uptime = &jstime.Duration{Duration: now().UTC().Sub(registrationInfo.StartedAt.Time)}
	requestBody, err := json.Marshal(registrationInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize integration registration as JSON: %w", err)
	}

	responseBody, err := anchore.Post(requestBody, "", RegisterAPIPathV2, anchoreDetails, "integration registration")
	if err != nil {
		return nil, err
	}

	registeredIntegration := Integration{}
	if err := json.Unmarshal(*responseBody, &registeredIntegration); err != nil {
		return nil, fmt.Errorf("failed to parse integration registration response: %w", err)
	}
	return &registeredIntegration, nil
}

// getRegistrationInfo resolves this agent's registration identity. Unlike the k8s
// agent there is no Deployment to key off, so the ECS task metadata endpoint takes
// that role, with config values overriding it.
func getRegistrationInfo(appConfig *config.AppConfig, metadata TaskMetadata, newUUID _NewUUID, now _Now) *Registration {
	scope := registrationScope(appConfig, metadata)

	registrationID := appConfig.Registration.RegistrationID
	if registrationID == "" && metadata.Family != "" {
		registrationID = scopedID(metadata.Family, scope)
	}
	if registrationID == "" {
		// Enterprise keys integrations on (registration_id, registration_instance_id), so a
		// generated id means every restart creates a brand new integration record.
		registrationID = newUUID().String()
		logger.Log.Warn(
			"No registration id could be determined, generating one. It will not be stable across restarts and "+
				"each restart will create a new integration in Anchore. Set anchore-registration.registration-id to avoid this.",
			"registrationID", registrationID)
	}

	// Enterprise keys an integration on the *pair* (registration_id,
	// registration_instance_id), so both halves have to survive a restart. The task ARN
	// is the obvious per-instance identifier and is deliberately not used as one (only its
	// account id segment is, as a scope qualifier — see registrationScope): ECS mints a
	// new task id on every deployment, scale event, health-check replacement or spot
	// interruption, so it would leave a new integration record behind each time (and
	// Enterprise only marks the old ones INACTIVE, it never removes them). The service
	// name, and failing that the task family, do survive. This mirrors
	// anchore-k8s-inventory, which uses the Deployment name rather than the pod name
	// whenever the agent is single-replica — which the ECS agent effectively always is.
	registrationInstanceID := appConfig.Registration.RegistrationInstanceID
	if instance := firstNonEmpty(metadata.ServiceName, metadata.Family); registrationInstanceID == "" && instance != "" {
		registrationInstanceID = scopedID(instance, scope)
	}
	if registrationInstanceID == "" {
		registrationInstanceID = firstNonEmpty(hostname(), newUUID().String())
		logger.Log.Warn(
			"No stable registration instance id could be determined, falling back to the hostname or a generated id. "+
				"In a container neither is stable across restarts, and each restart will create a new integration in Anchore. "+
				"Set anchore-registration.registration-instance-id to avoid this.",
			"registrationInstanceID", registrationInstanceID)
	}

	instanceName := firstNonEmpty(appConfig.Registration.IntegrationName, metadata.Family)

	appVersion := aeiVersion.FromBuild().Version
	if appVersion == aeiVersion.ValueNotProvided {
		appVersion = devVersion
	}

	logger.Log.Debug("Resolved integration registration values",
		"registrationID", registrationID, "registrationInstanceID", registrationInstanceID,
		"name", instanceName, "clusterName", metadata.Cluster)

	return &Registration{
		RegistrationID:         registrationID,
		RegistrationInstanceID: registrationInstanceID,
		Type:                   Type,
		Name:                   instanceName,
		Description:            appConfig.Registration.IntegrationDescription,
		Version:                appVersion,
		StartedAt:              jstime.Datetime{Time: now().UTC()},
		Uptime:                 new(jstime.Duration),
		Username:               appConfig.AnchoreDetails.User,
		AccountName:            appConfig.AnchoreDetails.Account,
		ExplicitlyAccountBound: []string{appConfig.AnchoreDetails.Account},
		// Namespaces/Namespace are Kubernetes-only and omitted for ECS.
		// Configuration is deliberately not sent: it would put AWS region and
		// credential-shaped material through the API for no benefit.
		Configuration:        nil,
		ClusterName:          metadata.Cluster,
		HealthReportInterval: appConfig.HealthReportIntervalSeconds,
	}
}

// registrationScope is what keeps a *derived* registration pair unique.
//
// Everything else there is to derive an identity from — the task definition family, the
// ECS service name — is a name the operator chose, and one Terraform/CloudFormation
// module deployed into two regions or two AWS accounts produces the same names in both.
// Enterprise keys an integration on (registration_id, registration_instance_id) without
// qualifying it by region or account, so two such agents would land on a single
// integration record: within one Anchore account the healthy agent's report clears the
// broken one's UNHEALTHY state every interval, and across accounts the second agent's
// registration migrates the row and the first agent's health reports 404 for the rest of
// its life. Neither is visible in the agent's own logs.
//
// The cluster the agent's *own* task runs in and the region it is configured to scan are
// both folded in. The cluster alone is not enough: the metadata endpoint reports it as an
// ARN on current ECS agents but as a bare cluster name on older ones, and two accounts
// running an identically named cluster in one region then derive the same pair. The AWS
// account id is therefore folded in as well, taken from the task ARN — it is a property of
// where the agent is deployed rather than of the task, so unlike the task id it survives
// task replacement and restarts.
func registrationScope(appConfig *config.AppConfig, metadata TaskMetadata) []string {
	return []string{awsAccountID(metadata.TaskARN), metadata.Cluster, appConfig.Region}
}

// awsAccountID returns the account id from an ECS task ARN
// (arn:<partition>:ecs:<region>:<account-id>:task/...), or "" if the value is not an ARN —
// the metadata endpoint may be absent entirely, in which case the scope simply narrows to
// what is available.
func awsAccountID(taskARN string) string {
	const (
		accountSegment = 4
		arnSegments    = 6
	)
	segments := strings.SplitN(taskARN, ":", arnSegments)
	if len(segments) < arnSegments || segments[0] != "arn" {
		return ""
	}
	return segments[accountSegment]
}

// scopedID qualifies an operator-chosen name with the parts of the scope that are
// available. The result is an opaque identity string, not a display name — Registration
// carries the human-readable name separately.
func scopedID(name string, scope []string) string {
	parts := make([]string, 0, len(scope)+1)
	parts = append(parts, name)
	for _, part := range scope {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, "/")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		logger.Log.Debug("Unable to determine hostname", "err", err)
		return ""
	}
	return name
}
