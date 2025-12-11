package inventory

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

type mockECSClient struct {
	ErrorOnListCluster         bool
	ErrorOnListTasks           bool
	ErrorOnListServices        bool
	ErrorOnDescribeTasks       bool
	ErrorOnListTagsForResource bool
	ErrorOnDescribeServices    bool
}

func (m *mockECSClient) ListClusters(ctx context.Context, _ *ecs.ListClustersInput, _ ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	if m.ErrorOnListCluster {
		return nil, errors.New("list cluster error")
	}
	return &ecs.ListClustersOutput{
		ClusterArns: []string{
			"arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
			"arn:aws:ecs:us-east-1:123456789012:cluster/cluster-2",
		},
	}, nil
}

func (m *mockECSClient) ListTasks(ctx context.Context, _ *ecs.ListTasksInput, _ ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	if m.ErrorOnListTasks {
		return nil, errors.New("list tasks error")
	}
	return &ecs.ListTasksOutput{
		TaskArns: []string{
			"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
			"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111",
		},
	}, nil
}

func (m *mockECSClient) ListServices(ctx context.Context, _ *ecs.ListServicesInput, _ ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	if m.ErrorOnListServices {
		return nil, errors.New("list services error")
	}
	return &ecs.ListServicesOutput{
		ServiceArns: []string{
			"arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
			"arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-2",
		},
	}, nil
}

func (m *mockECSClient) DescribeTasks(ctx context.Context, input *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	if m.ErrorOnDescribeTasks {
		return nil, errors.New("describe tasks error")
	}
	tasks := []ecstypes.Task{}
	for _, t := range input.Tasks {
		switch t {
		case "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000":
			tasks = append(tasks, ecstypes.Task{
				TaskArn: aws.String(
					"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
				),
				ClusterArn: aws.String("arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1"),
				TaskDefinitionArn: aws.String(
					"arn:aws:ecs:us-east-1:123456789012:task-definition/task-definition-1:1",
				),
				Group: aws.String("service:service-1"),
				Containers: []ecstypes.Container{
					{
						ContainerArn: aws.String(
							"arn:aws:ecs:us-east-1:123456789012:container/12345678-1234-1234-1234-111111111111",
						),
						Name:        aws.String("container-1"),
						Image:       aws.String("image-1"),
						ImageDigest: aws.String("sha256:1234567890123456789012345678901234567890123456789012345678901111"),
					},
					{
						ContainerArn: aws.String(
							"arn:aws:ecs:us-east-1:123456789012:container/12345678-1234-1234-1234-111111111112",
						),
						Name:        aws.String("container-2"),
						Image:       aws.String("image-2"),
						ImageDigest: aws.String("sha256:1234567890123456789012345678901234567890123456789012345678902222"),
					},
				},
			})
		case "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111":
			tasks = append(tasks, ecstypes.Task{
				TaskArn: aws.String(
					"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111",
				),
				ClusterArn: aws.String("arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1"),
				TaskDefinitionArn: aws.String(
					"arn:aws:ecs:us-east-1:123456789012:task-definition/task-definition-1:1",
				),
				Group: aws.String("service:service-1"),
				Containers: []ecstypes.Container{
					{
						ContainerArn: aws.String(
							"arn:aws:ecs:us-east-1:123456789012:container/12345678-1234-1234-1234-111111111113",
						),
						Name:        aws.String("container-3"),
						Image:       aws.String("image-3"),
						ImageDigest: aws.String("sha256:1234567890123456789012345678901234567890123456789012345678903333"),
					},
					{
						ContainerArn: aws.String(
							"arn:aws:ecs:us-east-1:123456789012:container/12345678-1234-1234-1234-111111111114",
						),
						Name:        aws.String("container-4-(same-image-as-3)"),
						Image:       aws.String("image-3"),
						ImageDigest: aws.String("sha256:1234567890123456789012345678901234567890123456789012345678903333"),
					},
				},
			})
		}
	}

	return &ecs.DescribeTasksOutput{Tasks: tasks}, nil
}

func (m *mockECSClient) ListTagsForResource(ctx context.Context, input *ecs.ListTagsForResourceInput, _ ...func(*ecs.Options)) (*ecs.ListTagsForResourceOutput, error) {
	if m.ErrorOnListTagsForResource {
		return nil, errors.New("list tags for resource error")
	}
	switch *input.ResourceArn {
	case "arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000":
		return &ecs.ListTagsForResourceOutput{
			Tags: []ecstypes.Tag{
				{
					Key:   aws.String("key-1"),
					Value: aws.String("value-1"),
				},
				{
					Key:   aws.String("key-2"),
					Value: aws.String("value-2"),
				},
			},
		}, nil
	case "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1":
		return &ecs.ListTagsForResourceOutput{
			Tags: []ecstypes.Tag{
				{
					Key:   aws.String("svc-key-1"),
					Value: aws.String("svc-value-1"),
				},
				{
					Key:   aws.String("svc-key-2"),
					Value: aws.String("svc-value-2"),
				},
			},
		}, nil
	default:
		return &ecs.ListTagsForResourceOutput{}, nil
	}
}

func (m *mockECSClient) DescribeServices(ctx context.Context, input *ecs.DescribeServicesInput, _ ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	if m.ErrorOnDescribeServices {
		return nil, errors.New("describe services error")
	}

	services := []ecstypes.Service{}
	for _, s := range input.Services {
		switch s {
		case "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1":
			services = append(services, ecstypes.Service{
				ServiceArn: aws.String(
					"arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
				),
				ClusterArn: aws.String("arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1"),
			})
		case "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-2":
			services = append(services, ecstypes.Service{
				ServiceArn: aws.String(
					"arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-2",
				),
				ClusterArn: aws.String("arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1"),
			})
		}
	}

	return &ecs.DescribeServicesOutput{Services: services}, nil
}
