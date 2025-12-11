package inventory

import (
	"context"

	ecs "github.com/aws/aws-sdk-go-v2/service/ecs"
)

// ECSAPI mirrors the ECS client operations used.
// Defined so tests can provide a mock implementation (aws-sdk-go-v2 removed ecsiface).
type ECSAPI interface {
	ListClusters(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	ListTasks(ctx context.Context, params *ecs.ListTasksInput, optFns ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	ListServices(ctx context.Context, params *ecs.ListServicesInput, optFns ...func(*ecs.Options)) (*ecs.ListServicesOutput, error)
	DescribeTasks(ctx context.Context, params *ecs.DescribeTasksInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
	DescribeServices(ctx context.Context, params *ecs.DescribeServicesInput, optFns ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error)
	ListTagsForResource(ctx context.Context, params *ecs.ListTagsForResourceInput, optFns ...func(*ecs.Options)) (*ecs.ListTagsForResourceOutput, error)
}
