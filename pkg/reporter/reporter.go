// Once In-Use Image data has been gathered, this package reports the data to Anchore
package reporter

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/h2non/gock"

	"github.com/anchore/ecs-inventory/internal/logger"
	"github.com/anchore/ecs-inventory/internal/tracker"
	"github.com/anchore/ecs-inventory/pkg/connection"
)

const v1ReportAPIPath = "v1/enterprise/ecs-inventory"
const v2ReportAPIPath = "v2/ecs-inventory"

var apiPath = v2ReportAPIPath

func Post(report Report, anchoreDetails connection.AnchoreInfo) error {
	logger.Log.Info("Reporting results to Anchore")
	defer tracker.TrackFunctionTime(time.Now(), fmt.Sprintf("Posting Inventory Report for cluster %s", report.ClusterARN))
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: anchoreDetails.HTTP.Insecure},
	} // #nosec G402
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(anchoreDetails.HTTP.TimeoutSeconds) * time.Second,
	}
	gock.InterceptClient(client)

	req, err := prepareRequest(report, anchoreDetails)

	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.StatusCode == 401 {
			return fmt.Errorf("failed to report data to Anchore, check credentials: %w", err)
		}
		return fmt.Errorf("failed to report data to Anchore: %w", err)
	}
	defer resp.Body.Close()

	// If we get a 404, make an assumption that the backend API support may have
	// changed, either because our default v2 is too new or because the API
	// service has been upgraded. Check the version, and if the version changes,
	// cache it and retry the request
	if resp.StatusCode == 404 {
		previousAPIPath := apiPath
		apiPath, err = fetchVersionedAPIPath(anchoreDetails)
		if err != nil {
			return fmt.Errorf("failed to validate Enterprise API: %w", err)
		}
		apiEndpoint, err := url.JoinPath(anchoreDetails.URL, apiPath)
		if err != nil {
			return fmt.Errorf("failed to parse API URL: %w", err)
		}

		if apiPath != previousAPIPath {
			logger.Log.Info("Retrying inventory report with new endpoint", "apiEndpoint", apiEndpoint)
			return Post(report, anchoreDetails)
		}

		return fmt.Errorf("failed to report data to Anchore: %+v", resp)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("failed to report data to Anchore: %+v", resp)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response from Anchore: %w", err)
	}
	if len(respBody) > 0 && !json.Valid(respBody) {
		logger.Log.Debug("Anchore response body: ", string(respBody))
		return fmt.Errorf("failed to report data to Anchore not a valid json response: %+v", resp)
	}
	logger.Log.Debug("Successfully reported results to Anchore")
	return nil
}

func prepareRequest(report Report, anchoreDetails connection.AnchoreInfo) (*http.Request, error) {
	apiEndpoint, err := url.JoinPath(anchoreDetails.URL, apiPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse API URL: %w", err)
	}
	logger.Log.Debug("Reporting results to Anchore", "Endpoint", apiEndpoint)

	reqBody, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize results as JSON: %w", err)
	}

	req, err := http.NewRequest("POST", apiEndpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to build request to report data to Anchore: %w", err)
	}
	req.SetBasicAuth(anchoreDetails.User, anchoreDetails.Password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-anchore-account", anchoreDetails.Account)

	return req, nil
}

type AnchoreVersion struct {
	API struct {
		Version string `json:"version"`
	} `json:"api"`
	DB struct {
		SchemaVersion string `json:"schema_version"`
	} `json:"db"`
	Service struct {
		Version string `json:"version"`
	} `json:"service"`
}

func fetchVersionedAPIPath(anchoreDetails connection.AnchoreInfo) (string, error) {
	logger.Log.Debug("Detecting Anchore API version")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: anchoreDetails.HTTP.Insecure},
	} // #nosec G402
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(anchoreDetails.HTTP.TimeoutSeconds) * time.Second,
	}
	gock.InterceptClient(client) // Required to use gock for testing custom client

	versionEndpoint, err := url.JoinPath(anchoreDetails.URL, "version")
	if err != nil {
		return v1ReportAPIPath, fmt.Errorf("failed to parse API URL: %w", err)
	}

	resp, err := client.Get(versionEndpoint)
	if err != nil {
		return v1ReportAPIPath, fmt.Errorf("failed to contact Anchore API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return v1ReportAPIPath, fmt.Errorf("failed to retrieve Anchore API version: %+v", resp)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return v1ReportAPIPath, fmt.Errorf("failed to read Anchore API version: %w", err)
	}

	ver := AnchoreVersion{}
	err = json.Unmarshal(body, &ver)
	if err != nil {
		return v1ReportAPIPath, fmt.Errorf("failed to parse API version: %w", err)
	}

	logger.Log.Debugf("Anchore API version: %v", ver)

	if ver.API.Version == "2" {
		return v2ReportAPIPath, nil
	}

	return v1ReportAPIPath, nil
}
