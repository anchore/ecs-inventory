//go:build integration

// These integration tests live in package pkg (not pkg/inventory) so they can drive the unexported
// multi-pass orchestration — preparePasses / readyPass — that turns the assume-role configuration
// into one isolated AWS config per account-region. They run against the same local moto server as
// the pkg/inventory integration tests (see test/integration/run.sh); with AWS_ENDPOINT_URL unset
// they skip, so `go test ./...` stays hermetic.
//
// Coverage boundary: moto emulates STS + the ECS control plane but does NOT populate a task's
// runtime Containers, so image extraction (the product's actual output) is not exercised here — that
// stays covered by the unit tests with a synthetic ECSAPI. These tests cover assume-role fan-out and
// per-pass account/region isolation up to cluster discovery.
package pkg

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/ecs-inventory/pkg/inventory"
)

// requireMoto skips the test unless an AWS endpoint (moto) is configured. `make integration` sets
// AWS_ENDPOINT_URL plus the fixed dummy credentials the AWS SDK's default chain resolves.
func requireMoto(t *testing.T) {
	t.Helper()
	if os.Getenv("AWS_ENDPOINT_URL") == "" {
		t.Skip("AWS_ENDPOINT_URL not set; run via `make integration` to start moto")
	}
}

// seedClusterInAccount creates a cluster in the account-region the given assumed role resolves to,
// using the production BuildAWSConfig path, and returns the created cluster ARN.
func seedClusterInAccount(t *testing.T, ctx context.Context, region, roleARN, name string) string {
	t.Helper()
	cfg, err := inventory.BuildAWSConfig(ctx, region, roleARN, "")
	require.NoError(t, err)
	out, err := ecs.NewFromConfig(cfg).CreateCluster(ctx, &ecs.CreateClusterInput{ClusterName: aws.String(name)})
	require.NoError(t, err)
	return *out.Cluster.ClusterArn
}

// listClusterARNs returns the cluster ARNs visible to the identity behind cfg.
func listClusterARNs(t *testing.T, ctx context.Context, cfg aws.Config) []string {
	t.Helper()
	out, err := ecs.NewFromConfig(cfg).ListClusters(ctx, &ecs.ListClustersInput{})
	require.NoError(t, err)
	return out.ClusterArns
}

// TestIntegration_MultiPassFanOutIsolatesAccounts is the end-to-end check for the feature's headline
// capability: one agent, multiple assume-role passes, each confined to its own account-region. It
// drives the real orchestration entry point — preparePasses builds one AWS config per pass via a
// genuine STS AssumeRole against moto — then runs each ready pass's discovery and asserts every pass
// sees ONLY its own account's cluster.
//
// This is the regression that would actually hurt in production and is otherwise untested: all
// passes silently collapsing onto one account, or leaking across accounts. moto enforces account
// isolation for assumed sessions, so cross-account leakage fails the NotContains assertions.
func TestIntegration_MultiPassFanOutIsolatesAccounts(t *testing.T) {
	requireMoto(t)
	SetLogger(&mockLogger{})
	ctx := context.Background()

	const (
		roleA = "arn:aws:iam::111111111111:role/anchore-ecs-inventory"
		roleB = "arn:aws:iam::222222222222:role/anchore-ecs-inventory"
	)
	clusterA := seedClusterInAccount(t, ctx, "us-east-1", roleA, "fanout-acct-a")
	clusterB := seedClusterInAccount(t, ctx, "eu-west-1", roleB, "fanout-acct-b")

	// The orchestration under test: one pass per role, each with its own region.
	passes := []inventoryPass{
		{region: "us-east-1", assumeRoleARN: roleA},
		{region: "eu-west-1", assumeRoleARN: roleB},
	}
	ready, err := preparePasses(ctx, inventory.BuildAWSConfig, passes)
	require.NoError(t, err)
	require.Len(t, ready, 2, "both passes should validate and be ready")

	// Run each ready pass's discovery using the config preparePasses built for it, and confirm strict
	// per-account isolation across the fan-out.
	seen := map[string][]string{}
	for _, p := range ready {
		seen[p.assumeRoleARN] = listClusterARNs(t, ctx, p.cfg)
	}

	assert.Contains(t, seen[roleA], clusterA, "pass A should discover account A's cluster")
	assert.NotContains(t, seen[roleA], clusterB, "pass A must NOT discover account B's cluster")
	assert.Contains(t, seen[roleB], clusterB, "pass B should discover account B's cluster")
	assert.NotContains(t, seen[roleB], clusterA, "pass B must NOT discover account A's cluster")
}
