package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/uuid"
	"github.com/hashicorp/go-version"

	"github.com/anchore/ecs-inventory/internal/anchore"
	"github.com/anchore/ecs-inventory/internal/config"
	"github.com/anchore/ecs-inventory/internal/logger"
	jstime "github.com/anchore/ecs-inventory/internal/time"
	ecsVersion "github.com/anchore/ecs-inventory/internal/version"
	"github.com/anchore/ecs-inventory/pkg/connection"
)

var requiredAnchoreVersion, _ = version.NewVersion("5.11")

var inventoryReportingActive = false

const Type = "ecs_inventory_agent"
const RegisterAPIPathV2 = "v2/system/integrations/registration"

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
	UUID                   string                 `json:"uuid,omitempty"`
	Type                   string                 `json:"type,omitempty"`
	Name                   string                 `json:"name,omitempty"`
	Description            string                 `json:"description,omitempty"`
	Version                string                 `json:"version,omitempty"`
	ReportedStatus         *HealthStatus          `json:"reported_status,omitempty"`
	IntegrationStatus      *LifeCycleStatus       `json:"integration_status,omitempty"`
	StartedAt              jstime.Datetime         `json:"started_at,omitempty"`
	LastSeen               *jstime.Datetime        `json:"last_seen,omitempty"`
	Uptime                 *jstime.Duration        `json:"uptime,omitempty"`
	Username               string                 `json:"username,omitempty"`
	AccountName            string                 `json:"account_name,omitempty"`
	Region                 string                 `json:"region,omitempty"`
	Configuration          map[string]interface{} `json:"configuration,omitempty"`
	HealthReportInterval   int                    `json:"health_report_interval,omitempty"`
	RegistrationID         string                 `json:"registration_id,omitempty"`
	RegistrationInstanceID string                 `json:"registration_instance_id,omitempty"`
}

type Registration struct {
	RegistrationID         string            `json:"registration_id,omitempty"`
	RegistrationInstanceID string            `json:"registration_instance_id,omitempty"`
	Type                   string            `json:"type,omitempty"`
	Name                   string            `json:"name,omitempty"`
	Description            string            `json:"description,omitempty"`
	Version                string            `json:"version,omitempty"`
	StartedAt              jstime.Datetime   `json:"started_at,omitempty"`
	Uptime                 *jstime.Duration  `json:"uptime,omitempty"`
	Username               string            `json:"username,omitempty"`
	Region                 string            `json:"region,omitempty"`
	Configuration          *config.AppConfig `json:"configuration,omitempty"`
	HealthReportInterval   int               `json:"health_report_interval,omitempty"`
}

type _NewUUID func() uuid.UUID

type _Now func() time.Time

func PerformRegistration(appConfig *config.AppConfig, ch Channels) (*Integration, error) {
	defer closeChannels(ch)

	_, err := awaitVersion(appConfig.AnchoreDetails, ch, -1, 2*time.Second, 1*time.Hour)
	if err != nil {
		return nil, err
	}

	registrationInfo := getRegistrationInfo(appConfig, uuid.New, time.Now)

	// Register this agent with enterprise
	registeredIntegration, err := register(registrationInfo, appConfig.AnchoreDetails, -1,
		2*time.Second, 10*time.Minute, time.Now)
	if err != nil {
		logger.Log.Errorf("Unable to register agent: %v", err)
		return nil, err
	}

	enableHealthReporting(ch, registeredIntegration)

	if !inventoryReportingActive {
		enableInventoryReporting(ch)
	}

	return registeredIntegration, nil
}

func awaitVersion(anchoreDetails connection.AnchoreInfo, ch Channels, maxRetry int, startBackoff, maxBackoff time.Duration) (*anchore.Version, error) {
	attempt := 0
	for {
		retry := false

		anchoreVersion, err := anchore.GetVersion(anchoreDetails)
		if err == nil {
			ver, vErr := version.NewVersion(anchoreVersion.Service.Version)
			if vErr != nil {
				logger.Log.Infof("Failed to parse received service version: %v. Will try again in %s", vErr, startBackoff)
				retry = true
			} else {
				logger.Log.Infof("Successfully determined service version: %s for Enterprise: %s",
					anchoreVersion.Service.Version, anchoreDetails.URL)
				if ver.GreaterThanOrEqual(requiredAnchoreVersion) {
					logger.Log.Infof("Proceeding with integration registration since Enterprise v%s supports that", anchoreVersion.Service.Version)
					return anchoreVersion, nil
				}
				if !inventoryReportingActive {
					logger.Log.Infof("Proceeding without integration registration and health reporting since Enterprise v%s does not support that",
						anchoreVersion.Service.Version)
					enableInventoryReporting(ch)
				}
				retry = true
			}
		}

		attempt++
		if maxRetry >= 0 && attempt > maxRetry {
			logger.Log.Infof("Failed to get Enterprise version after %d attempts", attempt)
			return nil, fmt.Errorf("failed to get Enterprise version after %d attempts", attempt)
		}

		if anchore.ServerIsOffline(err) {
			logger.Log.Infof("Anchore is offline. Will try again in %s", startBackoff)
			retry = true
		}

		if retry {
			time.Sleep(startBackoff)
			if startBackoff < maxBackoff {
				startBackoff = min(startBackoff*2, maxBackoff)
			}
			continue
		}

		logger.Log.Errorf("Failed to get service version for Enterprise: %s, %v", anchoreDetails.URL, err)
		return nil, err
	}
}

func GetChannels() Channels {
	return Channels{
		IntegrationObj:            make(chan *Integration),
		HealthReportingEnabled:    make(chan bool, 1), // buffered to prevent registration from blocking
		InventoryReportingEnabled: make(chan bool),
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
	inventoryReportingActive = true
	logger.Log.Info("Activating inventory reporting")
	// signal inventory reporting to start
	ch.InventoryReportingEnabled <- true
}

func register(registrationInfo *Registration, anchoreDetails connection.AnchoreInfo, maxRetry int,
	startBackoff, maxBackoff time.Duration, now _Now) (*Integration, error) {
	var err error

	attempt := 0
	for {
		var registeredIntegration *Integration

		registeredIntegration, err = doRegister(registrationInfo, anchoreDetails, now)
		if err == nil {
			logger.Log.Infof("Successfully registered %s agent: %s (registration_id:%s / registration_instance_id:%s) with %s",
				registrationInfo.Type, registrationInfo.Name, registrationInfo.RegistrationID,
				registrationInfo.RegistrationInstanceID, anchoreDetails.URL)
			logger.Log.Infof("This agent's integration uuid is %s", registeredIntegration.UUID)
			return registeredIntegration, nil
		}

		attempt++
		if maxRetry >= 0 && attempt > maxRetry {
			logger.Log.Errorf("Failed to register agent (registration_id:%s / registration_instance_id:%s) after %d attempts",
				registrationInfo.RegistrationID, registrationInfo.RegistrationInstanceID, attempt)
			return nil, fmt.Errorf("failed to register after %d attempts", attempt)
		}

		if anchore.ServerIsOffline(err) {
			logger.Log.Infof("Anchore is offline. Will try again in %s", startBackoff)
			time.Sleep(startBackoff)
			if startBackoff < maxBackoff {
				startBackoff = min(startBackoff*2, maxBackoff)
			}
			continue
		}

		if anchore.UserLacksAPIPrivileges(err) {
			logger.Log.Errorf("Specified user lacks required privileges to register and send health reports %v", err)
			return nil, err
		}

		if anchore.IncorrectCredentials(err) {
			logger.Log.Errorf("Failed to register due to invalid credentials (wrong username or password)")
			return nil, err
		}

		logger.Log.Errorf("Failed to register integration agent (registration_id:%s / registration_instance_id:%s): %v",
			registrationInfo.RegistrationID, registrationInfo.RegistrationInstanceID, err)
		return nil, err
	}
}

func doRegister(registrationInfo *Registration, anchoreDetails connection.AnchoreInfo, now _Now) (*Integration, error) {
	logger.Log.Infof("Registering %s agent: %s (registration_id:%s / registration_instance_id:%s) with %s",
		registrationInfo.Type, registrationInfo.Name, registrationInfo.RegistrationID,
		registrationInfo.RegistrationInstanceID, anchoreDetails.URL)

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
	err = json.Unmarshal(*responseBody, &registeredIntegration)
	return &registeredIntegration, err
}

func getRegistrationInfo(appConfig *config.AppConfig, newUUID _NewUUID, now _Now) *Registration {
	registrationID := appConfig.Registration.RegistrationID
	if registrationID == "" {
		logger.Log.Debugf("The registration_id value is not set. Generating UUIDv4 to use as registration_id")
		registrationID = newUUID().String()
	} else {
		logger.Log.Debugf("Using registration_id specified in config: %s", registrationID)
	}

	registrationInstanceID := newUUID().String()
	logger.Log.Debugf("Generated registration_instance_id: %s", registrationInstanceID)

	instanceName := appConfig.Registration.IntegrationName
	if instanceName == "" {
		instanceName = deriveIntegrationName(appConfig.Region)
	}
	description := appConfig.Registration.IntegrationDescription

	appVersion := ecsVersion.FromBuild().Version
	if appVersion == "[not provided]" {
		appVersion = "dev"
	}

	logger.Log.Debugf("Integration registration_id: %s, registration_instance_id: %s, name: %s, description: %s",
		registrationID, registrationInstanceID, instanceName, description)

	instance := Registration{
		RegistrationID:         registrationID,
		RegistrationInstanceID: registrationInstanceID,
		Type:                   Type,
		Name:                   instanceName,
		Description:            description,
		Version:                appVersion,
		StartedAt:              jstime.Datetime{Time: now().UTC()},
		Uptime:                 new(jstime.Duration),
		Username:               appConfig.AnchoreDetails.User,
		Region:                 appConfig.Region,
		Configuration:          nil,
		HealthReportInterval:   appConfig.HealthReportIntervalSeconds,
	}
	return &instance
}

// deriveIntegrationName builds a default integration name from the AWS account ID and region.
// Falls back to just the region if the account ID cannot be determined.
func deriveIntegrationName(region string) string {
	ctx := context.Background()
	optFns := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		optFns = append(optFns, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		logger.Log.Debugf("Failed to load AWS config for integration name derivation: %v", err)
		return fmt.Sprintf("ecs-inventory-%s", region)
	}

	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		logger.Log.Debugf("Failed to get AWS caller identity for integration name derivation: %v", err)
		return fmt.Sprintf("ecs-inventory-%s", region)
	}

	accountID := aws.ToString(identity.Account)
	logger.Log.Infof("Derived integration name from AWS account %s in region %s", accountID, region)
	return fmt.Sprintf("ecs-inventory-%s-%s", accountID, region)
}
