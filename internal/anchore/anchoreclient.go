// Package anchore is a small HTTP client for the Anchore Enterprise integration
// APIs used by integration registration and health reporting.
//
// Note: the in-use image inventory path deliberately keeps its own client in
// pkg/reporter, which carries v1/v2 endpoint fallback logic that these v2-only
// endpoints do not need.
package anchore

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/h2non/gock"

	"github.com/anchore/ecs-inventory/internal/logger"
	"github.com/anchore/ecs-inventory/internal/tracker"
	"github.com/anchore/ecs-inventory/pkg/connection"
)

const methodNotAllowedDetail = "Method Not Allowed"

type Version struct {
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

type ControllerErrorDetails struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

type APIErrorDetails struct {
	Message  string                 `json:"message"`
	Detail   map[string]interface{} `json:"detail"`
	HTTPCode int                    `json:"httpcode"`
}

type APIClientError struct {
	HTTPStatusCode         int
	Message                string
	Path                   string
	Method                 string
	Body                   *[]byte
	APIErrorDetails        *APIErrorDetails
	ControllerErrorDetails *ControllerErrorDetails
}

func (e *APIClientError) Error() string {
	return fmt.Sprintf("API error(%d): %s Path: %q %v %v", e.HTTPStatusCode, e.Message, e.Path,
		e.APIErrorDetails, e.ControllerErrorDetails)
}

// GetVersion returns the version information reported by Anchore Enterprise.
func GetVersion(anchoreDetails connection.AnchoreInfo) (*Version, error) {
	operation := "version get"
	defer tracker.TrackFunctionTime(time.Now(), fmt.Sprintf("Sent %s request to Anchore", operation))

	logger.Log.Debug("Determining Anchore service version")

	client := getClient(anchoreDetails)

	versionURL, err := getURL(anchoreDetails, "version", "")
	if err != nil {
		return nil, err
	}

	response, err := client.Get(versionURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if err := checkHTTPErrors(response, operation); err != nil {
		return nil, err
	}

	responseBody, err := getBody(response, operation)
	if err != nil {
		return nil, err
	}

	ver := Version{}
	if err := json.Unmarshal(*responseBody, &ver); err != nil {
		return nil, fmt.Errorf("failed to parse API version: %w", err)
	}
	return &ver, nil
}

// Post sends requestBody to path, substituting the "{{id}}" placeholder in path
// with id.
func Post(requestBody []byte, id, path string, anchoreDetails connection.AnchoreInfo, operation string) (*[]byte, error) {
	defer tracker.TrackFunctionTime(time.Now(), fmt.Sprintf("Sent %s request to Anchore", operation))

	logger.Log.Debug("Performing request to Anchore", "operation", operation, "path", substituteID(path, id))

	client := getClient(anchoreDetails)

	anchoreURL, err := getURL(anchoreDetails, path, id)
	if err != nil {
		return nil, err
	}

	request, err := getPostRequest(anchoreDetails, anchoreURL, requestBody, operation)
	if err != nil {
		return nil, err
	}

	return doPost(client, request, operation)
}

func substituteID(path, id string) string {
	return strings.Replace(path, "{{id}}", id, 1)
}

func getClient(anchoreDetails connection.AnchoreInfo) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: anchoreDetails.HTTP.Insecure}, // #nosec G402
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(anchoreDetails.HTTP.TimeoutSeconds) * time.Second,
	}
	gock.InterceptClient(client) // Required to use gock for testing custom client

	return client
}

// getURL appends path to the configured Anchore URL. It joins rather than
// concatenates so that an anchore.url carrying a base path (https://host/anchore)
// produces https://host/anchore/v2/... rather than https://host/anchorev2/...,
// matching how pkg/reporter builds the inventory endpoint.
func getURL(anchoreDetails connection.AnchoreInfo, path, id string) (string, error) {
	anchoreURL, err := url.JoinPath(anchoreDetails.URL, substituteID(path, id))
	if err != nil {
		return "", fmt.Errorf("failed to build path (%s) url: %w", path, err)
	}
	return anchoreURL, nil
}

func getPostRequest(anchoreDetails connection.AnchoreInfo, endpointURL string, reqBody []byte, operation string) (*http.Request, error) {
	request, err := http.NewRequest(http.MethodPost, endpointURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to prepare %s request to Anchore: %w", operation, err)
	}

	request.SetBasicAuth(anchoreDetails.User, anchoreDetails.Password)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("x-anchore-account", anchoreDetails.Account)
	return request, nil
}

func doPost(client *http.Client, request *http.Request, operation string) (*[]byte, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if err := checkHTTPErrors(response, operation); err != nil {
		return nil, err
	}

	return getBody(response, operation)
}

func checkHTTPErrors(response *http.Response, operation string) error {
	newError := func(msg string, apiErr *APIErrorDetails, controllerErr *ControllerErrorDetails) *APIClientError {
		return &APIClientError{
			Message:                msg,
			Path:                   response.Request.URL.Path,
			Method:                 response.Request.Method,
			Body:                   nil,
			HTTPStatusCode:         response.StatusCode,
			APIErrorDetails:        apiErr,
			ControllerErrorDetails: controllerErr,
		}
	}

	switch {
	case response.StatusCode >= 400 && response.StatusCode <= 599:
		msg := fmt.Sprintf("%s response from Anchore (during %s)", response.Status, operation)
		logger.Log.Debug(msg)

		respBody, _ := getBody(response, operation)
		if respBody == nil {
			return newError(msg, nil, nil)
		}

		// Depending on where an error is discovered during request processing on the
		// server, the error information in the response will be either an
		// APIErrorDetails or a ControllerErrorDetails
		apiError := APIErrorDetails{}
		if err := json.Unmarshal(*respBody, &apiError); err == nil {
			return newError(msg, &apiError, nil)
		}

		controllerError := ControllerErrorDetails{}
		if err := json.Unmarshal(*respBody, &controllerError); err == nil {
			return newError(msg, nil, &controllerError)
		}

		return newError(msg, nil, nil)
	case response.StatusCode < 200 || response.StatusCode > 299:
		msg := fmt.Sprintf("failed to perform %s to Anchore: %+v", operation, response)
		logger.Log.Debug(msg)
		return newError(msg, nil, nil)
	}
	return nil
}

func getBody(response *http.Response, operation string) (*[]byte, error) {
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s response body from Anchore: %w", operation, err)
	}

	// Check we received a valid JSON response from Anchore, this will help catch
	// any redirect responses where it returns HTML login pages e.g. Enterprise
	// running behind cloudflare where a login page is returned with the status 200
	if len(responseBody) > 0 && !json.Valid(responseBody) {
		logger.Log.Debug("Anchore response body was not valid json", "operation", operation, "body", string(responseBody))
		return nil, fmt.Errorf("%s response from Anchore is not valid json: %+v", operation, response)
	}
	return &responseBody, nil
}

// ServerIsOffline reports whether err indicates that Anchore could not be
// reached at all (as opposed to rejecting the request).
func ServerIsOffline(err error) bool {
	if os.IsTimeout(err) {
		return true
	}

	offlineErrors := []error{
		syscall.ENETDOWN,
		syscall.ENETUNREACH,
		syscall.ENETRESET,
		syscall.ECONNABORTED,
		syscall.ECONNRESET,
		syscall.ETIMEDOUT,
		syscall.ECONNREFUSED,
		syscall.EHOSTDOWN,
		syscall.EHOSTUNREACH,
	}

	for _, e := range offlineErrors {
		if errors.Is(err, e) {
			return true
		}
	}

	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return true
	}

	var apiClientError *APIClientError
	if errors.As(err, &apiClientError) {
		if apiClientError.HTTPStatusCode == http.StatusBadGateway ||
			apiClientError.HTTPStatusCode == http.StatusServiceUnavailable ||
			apiClientError.HTTPStatusCode == http.StatusGatewayTimeout {
			return true
		}
	}

	return false
}

// ServerLacksAgentHealthAPISupport reports whether err indicates that the
// Anchore deployment does not expose the integration registration/health
// reporting endpoints at all.
func ServerLacksAgentHealthAPISupport(err error) bool {
	var apiClientError *APIClientError
	if errors.As(err, &apiClientError) {
		if apiClientError.ControllerErrorDetails == nil {
			return false
		}

		if apiClientError.HTTPStatusCode == http.StatusNotFound &&
			strings.Contains(apiClientError.ControllerErrorDetails.Detail, "The requested URL was not found") {
			return true
		}

		if apiClientError.HTTPStatusCode == http.StatusMethodNotAllowed &&
			apiClientError.ControllerErrorDetails.Detail == methodNotAllowedDetail {
			return true
		}
	}

	return false
}

// UserLacksAPIPrivileges reports whether err indicates that the configured user
// is authenticated but lacks the RBAC permissions the request needs.
func UserLacksAPIPrivileges(err error) bool {
	var apiClientError *APIClientError

	if errors.As(err, &apiClientError) {
		if apiClientError.APIErrorDetails == nil {
			return false
		}

		if apiClientError.HTTPStatusCode == http.StatusForbidden &&
			strings.Contains(apiClientError.APIErrorDetails.Message, "Not authorized. Requires permissions") {
			return true
		}
	}
	return false
}

// IncorrectCredentials reports whether err indicates that the configured user
// does not exist or the password is wrong.
func IncorrectCredentials(err error) bool {
	var apiClientError *APIClientError

	return errors.As(err, &apiClientError) && apiClientError.HTTPStatusCode == http.StatusUnauthorized
}
