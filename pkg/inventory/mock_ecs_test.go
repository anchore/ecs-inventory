package inventory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

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

	// Multi-page responses for the List* calls. When a field is nil the call returns its
	// fixed single-page response instead, so tests that predate pagination are unaffected.
	ClusterPages [][]string
	TaskPages    [][]string
	ServicePages [][]string

	// The ID lists each Describe* call was made with, in order, so tests can check batching.
	DescribeTasksBatches    [][]string
	DescribeServicesBatches [][]string
}

// pageOf returns the page the token points at, plus the token for the page after it. Tokens
// are just the next page's index.
func pageOf(pages [][]string, token *string) ([]string, *string) {
	idx := 0
	if token != nil {
		idx, _ = strconv.Atoi(*token)
	}
	if idx >= len(pages) {
		return nil, nil
	}
	var next *string
	if idx+1 < len(pages) {
		next = aws.String(strconv.Itoa(idx + 1))
	}
	return pages[idx], next
}

func (m *mockECSClient) ListClusters(ctx context.Context, input *ecs.ListClustersInput, _ ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	if m.ErrorOnListCluster {
		return nil, errors.New("list cluster error")
	}
	if m.ClusterPages != nil {
		arns, next := pageOf(m.ClusterPages, input.NextToken)
		return &ecs.ListClustersOutput{ClusterArns: arns, NextToken: next}, nil
	}
	return &ecs.ListClustersOutput{
		ClusterArns: []string{
			"arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
			"arn:aws:ecs:us-east-1:123456789012:cluster/cluster-2",
		},
	}, nil
}

func (m *mockECSClient) ListTasks(ctx context.Context, input *ecs.ListTasksInput, _ ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	if m.ErrorOnListTasks {
		return nil, errors.New("list tasks error")
	}
	if m.TaskPages != nil {
		arns, next := pageOf(m.TaskPages, input.NextToken)
		return &ecs.ListTasksOutput{TaskArns: arns, NextToken: next}, nil
	}
	return &ecs.ListTasksOutput{
		TaskArns: []string{
			"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
			"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111",
		},
	}, nil
}

func (m *mockECSClient) ListServices(ctx context.Context, input *ecs.ListServicesInput, _ ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	if m.ErrorOnListServices {
		return nil, errors.New("list services error")
	}
	if m.ServicePages != nil {
		arns, next := pageOf(m.ServicePages, input.NextToken)
		return &ecs.ListServicesOutput{ServiceArns: arns, NextToken: next}, nil
	}
	return &ecs.ListServicesOutput{
		ServiceArns: []string{
			"arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
			"arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-2",
		},
	}, nil
}

const (
	syntheticTaskPrefix = "synthetic-task-"
	syntheticDigest     = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

// syntheticTaskARNs builds a task list long enough to span more than one DescribeTasks batch.
func syntheticTaskARNs(n int) []string {
	arns := make([]string, n)
	for i := range arns {
		arns[i] = fmt.Sprintf("%s%d", syntheticTaskPrefix, i)
	}
	return arns
}

// Every synthetic task shares one image digest, but only the first carries the readable tag.
// The rest can only be resolved from a tag map built across all of the batches at once.
func syntheticTask(arn string) ecstypes.Task {
	image := "app@" + syntheticDigest
	if arn == syntheticTaskPrefix+"0" {
		image = "app:v1"
	}
	return ecstypes.Task{
		TaskArn:    aws.String(arn),
		ClusterArn: aws.String("arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1"),
		TaskDefinitionArn: aws.String(
			"arn:aws:ecs:us-east-1:123456789012:task-definition/task-definition-1:1",
		),
		Containers: []ecstypes.Container{
			{
				ContainerArn: aws.String("container-" + arn),
				Name:         aws.String("container-" + arn),
				Image:        aws.String(image),
				ImageDigest:  aws.String(syntheticDigest),
			},
		},
	}
}

func (m *mockECSClient) DescribeTasks(ctx context.Context, input *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	if m.ErrorOnDescribeTasks {
		return nil, errors.New("describe tasks error")
	}
	m.DescribeTasksBatches = append(m.DescribeTasksBatches, input.Tasks)
	tasks := []ecstypes.Task{}
	for _, t := range input.Tasks {
		if strings.HasPrefix(t, syntheticTaskPrefix) {
			tasks = append(tasks, syntheticTask(t))
			continue
		}
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
	m.DescribeServicesBatches = append(m.DescribeServicesBatches, input.Services)

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
