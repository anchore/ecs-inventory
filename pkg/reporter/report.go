package reporter

type Report struct {
	Timestamp  string      `json:"timestamp"` // Should be generated using time.Now.UTC() and formatted according to RFC Y-M-DTH:M:SZ
	ClusterARN string      `json:"cluster_arn"`
	Containers []Container `json:"containers,omitempty"`
	Tasks      []Task      `json:"tasks,omitempty"`
	Services   []Service   `json:"services,omitempty"`
}

type Container struct {
	ARN         string `json:"arn"`
	ImageDigest string `json:"image_digest"`
	ImageTag    string `json:"image_tag"`
	TaskARN     string `json:"task_arn,omitempty"`
}

type Task struct {
	ARN        string            `json:"arn"`
	ServiceARN string            `json:"service_arn,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	TaskDefARN string            `json:"task_definition_arn,omitempty"`
}

type Service struct {
	ARN  string            `json:"arn"`
	Tags map[string]string `json:"tags,omitempty"`
}
