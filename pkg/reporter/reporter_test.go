package reporter

import (
	"testing"

	"github.com/anchore/ecs-inventory/pkg/connection"
)

func TestBuildUrl(t *testing.T) {
	anchoreDetails := connection.AnchoreInfo{
		URL:      "https://ancho.re",
		User:     "admin",
		Password: "foobar",
	}

	expectedURL := "https://ancho.re/v1/enterprise/ecs-inventory"
	actualURL, err := buildURL(anchoreDetails)
	if err != nil || expectedURL != actualURL {
		t.Errorf("Failed to build URL:\nexpected=%s\nactual=%s", expectedURL, actualURL)
	}
}
