package reporter

import (
	"io"
	"testing"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/ecs-inventory/pkg/connection"
)

func TestPost(t *testing.T) {
	defer gock.Off()

	type args struct {
		report         Report
		anchoreDetails connection.AnchoreInfo
	}
	tests := []struct {
		name            string
		args            args
		wantErr         bool
		expectedAPIPath string
	}{
		{
			name: "default post to v2",
			args: args{
				report: Report{},
				anchoreDetails: connection.AnchoreInfo{
					URL:      "https://ancho.re",
					User:     "admin",
					Password: "foobar",
					Account:  "test",
					HTTP: connection.HTTPConfig{
						TimeoutSeconds: 10,
						Insecure:       true,
					},
				},
			},
			wantErr:         false,
			expectedAPIPath: v2ReportAPIPath,
		},
		{
			name: "post to v1 when v2 is not found",
			args: args{
				report: Report{},
				anchoreDetails: connection.AnchoreInfo{
					URL:      "https://ancho.re",
					User:     "admin",
					Password: "foobar",
					Account:  "test",
					HTTP: connection.HTTPConfig{
						TimeoutSeconds: 10,
						Insecure:       true,
					},
				},
			},
			wantErr:         false,
			expectedAPIPath: v1ReportAPIPath,
		},
		{
			name: "error when v1 and v2 are not found",
			args: args{
				report: Report{},
				anchoreDetails: connection.AnchoreInfo{
					URL:      "https://ancho.re",
					User:     "admin",
					Password: "foobar",
					Account:  "test",
					HTTP: connection.HTTPConfig{
						TimeoutSeconds: 10,
						Insecure:       true,
					},
				},
			},
			wantErr:         true,
			expectedAPIPath: v1ReportAPIPath,
		},
		{
			name: "error when api response is not JSON",
			args: args{
				report: Report{},
				anchoreDetails: connection.AnchoreInfo{
					URL:      "https://ancho.re",
					User:     "admin",
					Password: "foobar",
					Account:  "test",
					HTTP: connection.HTTPConfig{
						TimeoutSeconds: 10,
						Insecure:       true,
					},
				},
			},
			wantErr:         true,
			expectedAPIPath: v2ReportAPIPath,
		},
	}
	for _, tt := range tests {
		switch tt.name {
		case "default post to v2":
			gock.New("https://ancho.re").
				Post(v2ReportAPIPath).
				Reply(201).
				JSON(map[string]interface{}{})
		case "post to v1 when v2 is not found":
			gock.New("https://ancho.re").
				Post(v2ReportAPIPath).
				Reply(404)
			gock.New("https://ancho.re").
				Post(v1ReportAPIPath).
				Reply(201).
				JSON(map[string]interface{}{})
			gock.New("https://ancho.re").
				Get("/version").
				Reply(200).
				JSON(map[string]interface{}{
					"api":     map[string]interface{}{},
					"db":      map[string]interface{}{"schema_version": "400"},
					"service": map[string]interface{}{"version": "4.8.0"},
				})
		case "error when v1 and v2 are not found":
			gock.New("https://ancho.re").
				Post(v2ReportAPIPath).
				Reply(404)
			gock.New("https://ancho.re").
				Get("/version").
				Reply(404)
		case "error when api response is not JSON":
			gock.New("https://ancho.re").
				Post(v2ReportAPIPath).
				Reply(200).
				BodyString("not json")
		}

		t.Run(tt.name, func(t *testing.T) {
			// Reset apiPath to the default each test run
			apiPath = v2ReportAPIPath

			err := Post(tt.args.report, tt.args.anchoreDetails)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedAPIPath, apiPath)
			}
		})
	}
}

// Simulate a handover from Enterprise 4.x to 5.x
// In this case v1 should be used initially instead of v2 then when v1 is no longer available v2 should be used
func TestPostSimulateV1ToV2HandoverFromEnterprise4Xto5X(t *testing.T) {
	defer gock.Off()

	testReport := Report{}
	testAnchoreDetails := connection.AnchoreInfo{
		URL:      "https://ancho.re",
		User:     "admin",
		Password: "foobar",
		Account:  "test",
		HTTP: connection.HTTPConfig{
			TimeoutSeconds: 10,
			Insecure:       true,
		},
	}

	apiPath = v2ReportAPIPath

	// After the first post to default v2, the apiPath should be set to v1
	gock.New("https://ancho.re").
		Post(v2ReportAPIPath).
		Reply(404)
	gock.New("https://ancho.re").
		Get("/version").
		Reply(200).
		JSON(map[string]interface{}{
			"api":     map[string]interface{}{},
			"db":      map[string]interface{}{"schema_version": "400"},
			"service": map[string]interface{}{"version": "4.8.0"},
		})
	gock.New("https://ancho.re").
		Post(v1ReportAPIPath).
		Reply(201).
		JSON(map[string]interface{}{})
	err := Post(testReport, testAnchoreDetails)
	assert.NoError(t, err)
	assert.Equal(t, v1ReportAPIPath, apiPath)

	// Simulate upgrade to Enterprise 5.x, v1 should no longer be available
	gock.New("https://ancho.re").
		Post(v1ReportAPIPath).
		Reply(404)
	gock.New("https://ancho.re").
		Get("/version").
		Reply(200).
		JSON(map[string]interface{}{
			"api":     map[string]interface{}{"version": "2"},
			"db":      map[string]interface{}{"schema_version": "400"},
			"service": map[string]interface{}{"version": "4.8.0"},
		})
	gock.New("https://ancho.re").
		Post(v2ReportAPIPath).
		Reply(201).
		JSON(map[string]interface{}{})
	err = Post(testReport, testAnchoreDetails)
	assert.NoError(t, err)
	assert.Equal(t, v2ReportAPIPath, apiPath)
}

func Test_prepareRequest(t *testing.T) {
	// Reset apiPath to default
	apiPath = v2ReportAPIPath

	report := Report{
		Timestamp:  "2024-01-01T00:00:00Z",
		ClusterARN: "arn:aws:ecs:us-east-1:123456789012:cluster/test",
		Containers: []Container{
			{
				ARN:         "arn:aws:ecs:us-east-1:123456789012:container/abc",
				ImageTag:    "nginx:latest",
				ImageDigest: "sha256:abc123",
				TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/test/task1",
			},
		},
	}

	anchoreDetails := connection.AnchoreInfo{
		URL:      "https://ancho.re",
		User:     "admin",
		Password: "foobar",
		Account:  "testaccount",
	}

	req, err := prepareRequest(report, anchoreDetails)
	require.NoError(t, err)

	// Verify URL
	assert.Equal(t, "https://ancho.re/v2/ecs-inventory", req.URL.String())

	// Verify method
	assert.Equal(t, "POST", req.Method)

	// Verify basic auth
	user, pass, ok := req.BasicAuth()
	assert.True(t, ok)
	assert.Equal(t, "admin", user)
	assert.Equal(t, "foobar", pass)

	// Verify Content-Type
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))

	// Verify x-anchore-account header
	assert.Equal(t, "testaccount", req.Header.Get("x-anchore-account"))

	// Verify body contains report data
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "arn:aws:ecs:us-east-1:123456789012:cluster/test")
	assert.Contains(t, string(body), "nginx:latest")
}

func Test_fetchVersionedAPIPath(t *testing.T) {
	t.Run("returns v2 path when API version is 2", func(t *testing.T) {
		defer gock.Off()
		gock.New("https://ancho.re").
			Get("/version").
			Reply(200).
			JSON(map[string]interface{}{
				"api":     map[string]interface{}{"version": "2"},
				"db":      map[string]interface{}{"schema_version": "400"},
				"service": map[string]interface{}{"version": "5.0.0"},
			})

		anchoreDetails := connection.AnchoreInfo{
			URL:      "https://ancho.re",
			User:     "admin",
			Password: "foobar",
			HTTP: connection.HTTPConfig{
				TimeoutSeconds: 10,
				Insecure:       true,
			},
		}

		path, err := fetchVersionedAPIPath(anchoreDetails)
		assert.NoError(t, err)
		assert.Equal(t, v2ReportAPIPath, path)
	})

	t.Run("returns v1 path when API version is not 2", func(t *testing.T) {
		defer gock.Off()
		gock.New("https://ancho.re").
			Get("/version").
			Reply(200).
			JSON(map[string]interface{}{
				"api":     map[string]interface{}{},
				"db":      map[string]interface{}{"schema_version": "400"},
				"service": map[string]interface{}{"version": "4.8.0"},
			})

		anchoreDetails := connection.AnchoreInfo{
			URL:      "https://ancho.re",
			User:     "admin",
			Password: "foobar",
			HTTP: connection.HTTPConfig{
				TimeoutSeconds: 10,
				Insecure:       true,
			},
		}

		path, err := fetchVersionedAPIPath(anchoreDetails)
		assert.NoError(t, err)
		assert.Equal(t, v1ReportAPIPath, path)
	})

	t.Run("returns v1 path on non-200 response", func(t *testing.T) {
		defer gock.Off()
		gock.New("https://ancho.re").
			Get("/version").
			Reply(500)

		anchoreDetails := connection.AnchoreInfo{
			URL:      "https://ancho.re",
			User:     "admin",
			Password: "foobar",
			HTTP: connection.HTTPConfig{
				TimeoutSeconds: 10,
				Insecure:       true,
			},
		}

		path, err := fetchVersionedAPIPath(anchoreDetails)
		assert.Error(t, err)
		assert.Equal(t, v1ReportAPIPath, path)
	})
}
