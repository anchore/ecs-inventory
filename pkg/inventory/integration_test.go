//go:build integration

// Package inventory integration tests exercise the code paths that unit tests with a mocked ECSAPI
// cannot: the real AWS SDK wiring for STS AssumeRole, credential resolution, region handling, and
// the ECS control-plane calls, plus reporting to a stand-in Anchore HTTP API.
//
// They run against a local moto server (https://github.com/getmoto/moto) that emulates STS + ECS.
// LocalStack's community edition does not implement ECS, so moto is used instead. moto does NOT
// populate a task's runtime Containers, so image-level extraction stays covered by the unit tests in
// ecs_test.go with a synthetic ECSAPI; these tests cover everything up to and including report
// assembly for clusters/services and delivery to Anchore.
//
// Run via `make integration`, which starts/stops the pinned moto container and sets the environment
// this test reads. When AWS_ENDPOINT_URL is unset the test skips, so `go test ./...` stays hermetic.
package inventory

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/h2non/gock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/ecs-inventory/pkg/connection"
	"github.com/anchore/ecs-inventory/pkg/reporter"
)

const integrationRegion = "us-east-1"

// requireMoto skips the test unless an AWS endpoint (moto) is configured. `make integration` sets
// AWS_ENDPOINT_URL plus the base credentials the AWS SDK's default chain resolves.
func requireMoto(t *testing.T) {
	t.Helper()
	if os.Getenv("AWS_ENDPOINT_URL") == "" {
		t.Skip("AWS_ENDPOINT_URL not set; run via `make integration` to start moto")
	}
}

// seedClient returns an ECS client using the base (non-assumed) credentials, pointed at moto via the
// AWS SDK's standard AWS_ENDPOINT_URL handling. It is used only to create the fixtures the assumed
// role then reads back.
func seedClient(t *testing.T, ctx context.Context) *ecs.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(integrationRegion))
	require.NoError(t, err)
	return ecs.NewFromConfig(cfg)
}

// seedCluster creates a cluster with one service (backed by a registered task definition) and tags,
// returning the cluster and service ARNs.
func seedCluster(t *testing.T, ctx context.Context, client *ecs.Client, name string) (clusterARN, serviceARN string) {
	t.Helper()

	cluster, err := client.CreateCluster(ctx, &ecs.CreateClusterInput{ClusterName: aws.String(name)})
	require.NoError(t, err)
	clusterARN = *cluster.Cluster.ClusterArn

	_, err = client.RegisterTaskDefinition(ctx, &ecs.RegisterTaskDefinitionInput{
		Family: aws.String(name + "-family"),
		ContainerDefinitions: []ecstypes.ContainerDefinition{
			{Name: aws.String("app"), Image: aws.String("nginx:1.25"), Memory: aws.Int32(128)},
		},
	})
	require.NoError(t, err)

	service, err := client.CreateService(ctx, &ecs.CreateServiceInput{
		Cluster:        aws.String(name),
		ServiceName:    aws.String(name + "-svc"),
		TaskDefinition: aws.String(name + "-family"),
		DesiredCount:   aws.Int32(1),
		Tags:           []ecstypes.Tag{{Key: aws.String("team"), Value: aws.String("platform")}},
	})
	require.NoError(t, err)
	serviceARN = *service.Service.ServiceArn

	return clusterARN, serviceARN
}

// TestIntegration_AssumeRoleIsolatesByAccountAndRegion proves the assume-role path actually switches
// AWS accounts/regions instead of silently falling back to ambient credentials. It seeds one cluster
// into account A (us-east-1) and another into account B (eu-west-1), each through its OWN assumed
// role, so the two live in genuinely separate moto account-regions. Discovering through each role
// must then return only that role's cluster.
//
// moto enforces account isolation for assumed sessions, so the NotContains assertions are the real
// teeth: if configureAssumeRole were a no-op (client silently on ambient creds) or a pass used the
// wrong region, a role would see the other account's cluster and the test fails loudly. The earlier
// same-account version of this test could not detect either failure.
func TestIntegration_AssumeRoleIsolatesByAccountAndRegion(t *testing.T) {
	requireMoto(t)
	ctx := context.Background()

	const (
		roleA = "arn:aws:iam::111111111111:role/anchore-ecs-inventory"
		roleB = "arn:aws:iam::222222222222:role/anchore-ecs-inventory"
	)

	// Seed each cluster through its own assumed role so moto places it in that role's account-region.
	cfgA, err := BuildAWSConfig(ctx, "us-east-1", roleA, "")
	require.NoError(t, err)
	clusterA, _ := seedCluster(t, ctx, ecs.NewFromConfig(cfgA), "acct-a-cluster")

	cfgB, err := BuildAWSConfig(ctx, "eu-west-1", roleB, "")
	require.NoError(t, err)
	clusterB, _ := seedCluster(t, ctx, ecs.NewFromConfig(cfgB), "acct-b-cluster")

	// Confirm the assumed sessions really landed in the two distinct accounts.
	assert.Contains(t, clusterA, ":111111111111:", "cluster A should live in account A")
	assert.Contains(t, clusterB, ":222222222222:", "cluster B should live in account B")

	// Discover through each role's config using the production cluster-listing path.
	seenByA, err := fetchClusters(ctx, ecs.NewFromConfig(cfgA))
	require.NoError(t, err)
	seenByB, err := fetchClusters(ctx, ecs.NewFromConfig(cfgB))
	require.NoError(t, err)

	assert.Contains(t, seenByA, clusterA, "role A should discover account A's cluster")
	assert.NotContains(t, seenByA, clusterB, "role A must NOT discover account B's cluster")
	assert.Contains(t, seenByB, clusterB, "role B should discover account B's cluster")
	assert.NotContains(t, seenByB, clusterA, "role B must NOT discover account A's cluster")
}

// TestIntegration_ReportDeliveredToAnchore drives the assembled report through the real reporter to a
// stand-in Anchore HTTP server, asserting the payload actually sent over the wire. The httptest
// server is the "mocked Anchore API"; gock networking is enabled so the reporter's intercepted
// client reaches it.
func TestIntegration_ReportDeliveredToAnchore(t *testing.T) {
	requireMoto(t)
	ctx := context.Background()

	clusterARN, serviceARN := seedCluster(t, ctx, seedClient(t, ctx), "report-delivery")

	cfg, err := BuildAWSConfig(ctx, integrationRegion, "arn:aws:iam::123456789012:role/anchore-ecs-inventory", "")
	require.NoError(t, err)
	report, err := GetInventoryReportForCluster(ctx, clusterARN, ecs.NewFromConfig(cfg), "")
	require.NoError(t, err)

	var got []reporter.Report
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/ecs-inventory", r.URL.Path)
		assert.Equal(t, "admin", r.Header.Get("x-anchore-account"))
		body, _ := io.ReadAll(r.Body)
		var rep reporter.Report
		require.NoError(t, json.Unmarshal(body, &rep))
		got = append(got, rep)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	// The reporter installs a gock transport on its HTTP client; enable real networking so the
	// unmatched request passes through to the httptest server.
	gock.EnableNetworking()
	defer gock.DisableNetworking()
	defer gock.OffAll()

	anchore := connection.AnchoreInfo{
		URL:      srv.URL,
		User:     "admin",
		Password: "admin",
		Account:  "admin",
		HTTP:     connection.HTTPConfig{TimeoutSeconds: 10},
	}

	require.NoError(t, HandleReport(report, anchore, false, false))

	require.Len(t, got, 1, "Anchore should have received exactly one report")
	assert.Equal(t, clusterARN, got[0].ClusterARN)
	deliveredServiceARNs := make([]string, 0, len(got[0].Services))
	for _, s := range got[0].Services {
		deliveredServiceARNs = append(deliveredServiceARNs, s.ARN)
	}
	assert.Contains(t, deliveredServiceARNs, serviceARN)
}
