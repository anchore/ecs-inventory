package anchore

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"testing"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/ecs-inventory/internal/logger"
	"github.com/anchore/ecs-inventory/pkg/connection"
)

func init() {
	logger.Log = &logger.NoOpLogger{}
}

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

func TestGetVersion(t *testing.T) {
	defer gock.Off()
	gock.New("https://ancho.re").
		Get("/version").
		Reply(200).
		JSON(map[string]interface{}{
			"api":     map[string]string{"version": "2"},
			"db":      map[string]string{"schema_version": "6.2.0"},
			"service": map[string]string{"version": "6.2.0"},
		})

	ver, err := GetVersion(testAnchoreDetails)

	require.NoError(t, err)
	assert.Equal(t, "2", ver.API.Version)
	assert.Equal(t, "6.2.0", ver.Service.Version)
	assert.True(t, gock.IsDone())
}

func TestGetVersionNotJSON(t *testing.T) {
	defer gock.Off()
	gock.New("https://ancho.re").
		Get("/version").
		Reply(200).
		BodyString("<html>login page</html>")

	_, err := GetVersion(testAnchoreDetails)

	assert.ErrorContains(t, err, "not valid json")
}

func TestPost(t *testing.T) {
	defer gock.Off()
	gock.New("https://ancho.re").
		Post("/v2/system/integrations/some-uuid/health-report").
		MatchHeader("Content-Type", "application/json").
		MatchHeader("x-anchore-account", "test-account").
		BasicAuth("admin", "foobar").
		JSON(map[string]interface{}{"hello": "world"}).
		Reply(201).
		BodyString("")

	body, err := Post([]byte(`{"hello":"world"}`), "some-uuid",
		"v2/system/integrations/{{id}}/health-report", testAnchoreDetails, "health report")

	require.NoError(t, err)
	assert.Empty(t, *body)
	assert.True(t, gock.IsDone())
}

func TestPostAPIError(t *testing.T) {
	defer gock.Off()
	gock.New("https://ancho.re").
		Post("/v2/system/integrations/registration").
		Reply(403).
		JSON(map[string]interface{}{
			"message":  "Not authorized. Requires permissions: domain=test-account action=reportHealth",
			"detail":   map[string]interface{}{"error_codes": []string{}},
			"httpcode": 403,
		})

	_, err := Post([]byte("{}"), "", "v2/system/integrations/registration", testAnchoreDetails, "registration")

	var apiClientError *APIClientError
	require.ErrorAs(t, err, &apiClientError)
	assert.Equal(t, http.StatusForbidden, apiClientError.HTTPStatusCode)
	require.NotNil(t, apiClientError.APIErrorDetails)
	assert.Nil(t, apiClientError.ControllerErrorDetails)
	assert.True(t, UserLacksAPIPrivileges(err))
	assert.Contains(t, apiClientError.Error(), "403")
}

func TestPostControllerError(t *testing.T) {
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

	_, err := Post([]byte("{}"), "", "v2/system/integrations/registration", testAnchoreDetails, "registration")

	var apiClientError *APIClientError
	require.ErrorAs(t, err, &apiClientError)
	assert.Equal(t, http.StatusNotFound, apiClientError.HTTPStatusCode)
	require.NotNil(t, apiClientError.ControllerErrorDetails)
	assert.Nil(t, apiClientError.APIErrorDetails)
	assert.True(t, ServerLacksAgentHealthAPISupport(err))
}

func TestPostServerErrorNoBody(t *testing.T) {
	defer gock.Off()
	gock.New("https://ancho.re").
		Post("/v2/system/integrations/registration").
		Reply(500).
		BodyString("")

	_, err := Post([]byte("{}"), "", "v2/system/integrations/registration", testAnchoreDetails, "registration")

	var apiClientError *APIClientError
	require.ErrorAs(t, err, &apiClientError)
	assert.Equal(t, http.StatusInternalServerError, apiClientError.HTTPStatusCode)
	assert.Nil(t, apiClientError.APIErrorDetails)
	assert.Nil(t, apiClientError.ControllerErrorDetails)
}

func TestPostBadURL(t *testing.T) {
	details := testAnchoreDetails
	details.URL = "://not-a-url"

	_, err := Post([]byte("{}"), "", "v2/system/integrations/registration", details, "registration")

	assert.ErrorContains(t, err, "failed to build path")
}

func TestGetURL(t *testing.T) {
	const healthReportPath = "v2/system/integrations/{{id}}/health-report"

	tests := []struct {
		name    string
		baseURL string
		path    string
		id      string
		want    string
	}{
		{
			name:    "substitutes the id",
			baseURL: "https://ancho.re",
			path:    healthReportPath,
			id:      "abc-123",
			want:    "https://ancho.re/v2/system/integrations/abc-123/health-report",
		},
		{
			name:    "trailing slash on the base url",
			baseURL: "https://ancho.re/",
			path:    healthReportPath,
			id:      "abc-123",
			want:    "https://ancho.re/v2/system/integrations/abc-123/health-report",
		},
		{
			// concatenating rather than joining would yield /anchorev2/... and 404
			name:    "base path on the base url",
			baseURL: "https://ancho.re/anchore",
			path:    healthReportPath,
			id:      "abc-123",
			want:    "https://ancho.re/anchore/v2/system/integrations/abc-123/health-report",
		},
		{
			name:    "base path with a trailing slash",
			baseURL: "https://ancho.re/anchore/",
			path:    healthReportPath,
			id:      "abc-123",
			want:    "https://ancho.re/anchore/v2/system/integrations/abc-123/health-report",
		},
		{
			name:    "port and base path",
			baseURL: "http://localhost:8228/anchore",
			path:    "v2/system/integrations/registration",
			id:      "",
			want:    "http://localhost:8228/anchore/v2/system/integrations/registration",
		},
		{
			name:    "version probe",
			baseURL: "https://ancho.re/anchore",
			path:    "version",
			id:      "",
			want:    "https://ancho.re/anchore/version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			details := testAnchoreDetails
			details.URL = tt.baseURL

			got, err := getURL(details, tt.path, tt.id)

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestServerIsOffline(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "connection refused", err: fmt.Errorf("dial: %w", syscall.ECONNREFUSED), want: true},
		{name: "host unreachable", err: syscall.EHOSTUNREACH, want: true},
		{name: "dns error", err: &net.DNSError{Err: "no such host", IsNotFound: true}, want: true},
		{name: "bad gateway", err: &APIClientError{HTTPStatusCode: http.StatusBadGateway}, want: true},
		{name: "service unavailable", err: &APIClientError{HTTPStatusCode: http.StatusServiceUnavailable}, want: true},
		{name: "gateway timeout", err: &APIClientError{HTTPStatusCode: http.StatusGatewayTimeout}, want: true},
		{name: "bad request", err: &APIClientError{HTTPStatusCode: http.StatusBadRequest}, want: false},
		{name: "unrelated", err: errors.New("boom"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ServerIsOffline(tt.err))
		})
	}
}

func TestServerLacksAgentHealthAPISupport(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{
			name: "404 with not found detail",
			err: &APIClientError{
				HTTPStatusCode:         http.StatusNotFound,
				ControllerErrorDetails: &ControllerErrorDetails{Detail: "The requested URL was not found on the server."},
			},
			want: true,
		},
		{
			name: "405 method not allowed",
			err: &APIClientError{
				HTTPStatusCode:         http.StatusMethodNotAllowed,
				ControllerErrorDetails: &ControllerErrorDetails{Detail: methodNotAllowedDetail},
			},
			want: true,
		},
		{
			name: "404 without controller details",
			err:  &APIClientError{HTTPStatusCode: http.StatusNotFound},
			want: false,
		},
		{
			name: "400 bad request",
			err: &APIClientError{
				HTTPStatusCode:         http.StatusBadRequest,
				ControllerErrorDetails: &ControllerErrorDetails{Detail: "invalid type"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ServerLacksAgentHealthAPISupport(tt.err))
		})
	}
}

func TestUserLacksAPIPrivileges(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{
			name: "403 with permissions message",
			err: &APIClientError{
				HTTPStatusCode:  http.StatusForbidden,
				APIErrorDetails: &APIErrorDetails{Message: "Not authorized. Requires permissions: action=reportHealth"},
			},
			want: true,
		},
		{
			name: "403 without api details",
			err:  &APIClientError{HTTPStatusCode: http.StatusForbidden},
			want: false,
		},
		{
			name: "401",
			err: &APIClientError{
				HTTPStatusCode:  http.StatusUnauthorized,
				APIErrorDetails: &APIErrorDetails{Message: "Unauthorized"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, UserLacksAPIPrivileges(tt.err))
		})
	}
}

func TestIncorrectCredentials(t *testing.T) {
	assert.True(t, IncorrectCredentials(&APIClientError{HTTPStatusCode: http.StatusUnauthorized}))
	assert.False(t, IncorrectCredentials(&APIClientError{HTTPStatusCode: http.StatusForbidden}))
	assert.False(t, IncorrectCredentials(errors.New("boom")))
	assert.False(t, IncorrectCredentials(nil))
}
