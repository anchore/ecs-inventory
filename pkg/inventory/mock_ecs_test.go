package inventory

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/ecs/ecsiface"
)

type mockECSClient struct {
	ecsiface.ECSAPI
}

func (m *mockECSClient) ListClusters(*ecs.ListClustersInput) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{
		ClusterArns: []*string{
			aws.String("arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1"),
			aws.String("arn:aws:ecs:us-east-1:123456789012:cluster/cluster-2"),
		},
	}, nil
}

func (m *mockECSClient) ListTasks(*ecs.ListTasksInput) (*ecs.ListTasksOutput, error) {
	return &ecs.ListTasksOutput{
		TaskArns: []*string{
			aws.String("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000"),
			aws.String("arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111"),
		},
	}, nil
}

func (m *mockECSClient) DescribeTasks(*ecs.DescribeTasksInput) (*ecs.DescribeTasksOutput, error) {
	return &ecs.DescribeTasksOutput{
		Tasks: []*ecs.Task{
			{
				TaskArn: aws.String(
					"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-000000000000",
				),
				ClusterArn: aws.String("arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1"),
				TaskDefinitionArn: aws.String(
					"arn:aws:ecs:us-east-1:123456789012:task-definition/task-definition-1:1",
				),
				Containers: []*ecs.Container{
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
			},
			{
				TaskArn: aws.String(
					"arn:aws:ecs:us-east-1:123456789012:task/cluster-1/12345678-1234-1234-1234-111111111111",
				),
				ClusterArn: aws.String("arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1"),
				TaskDefinitionArn: aws.String(
					"arn:aws:ecs:us-east-1:123456789012:task-definition/task-definition-1:1",
				),
				Containers: []*ecs.Container{
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
			},
		},
	}, nil
}
