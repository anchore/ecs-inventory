package reporter

type Report struct {
	Timestamp   string      `json:"timestamp,omitempty"` // Should be generated using time.Now.UTC() and formatted according to RFC Y-M-DTH:M:SZ
	ClusterName string      `json:"cluster_name,omitempty"`
	Containers  []Container `json:"containers,omitempty"`
	Tasks       []Task      `json:"tasks,omitempty"`
}

type Container struct {
	ARN         string `json:"arn"`
	ImageDigest string `json:"image_digest"`
	ImageTag    string `json:"image_tag"`
	TaskARN     string `json:"task_arn,omitempty"`
}

type Task struct {
	ARN        string            `json:"arn"`
	ClusterARN string            `json:"cluster_arn,omitempty"`
	ServiceARN string            `json:"service_arn,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	TaskDefARN string            `json:"task_definition_arn,omitempty"`
}

type Service struct {
	ARN        string            `json:"arn"`
	ClusterARN string            `json:"cluster_arn,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
}
