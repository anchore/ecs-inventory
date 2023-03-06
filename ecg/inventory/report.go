package inventory

type Report struct {
	Timestamp     string       `json:"timestamp,omitempty"` // Should be generated using time.Now.UTC() and formatted according to RFC Y-M-DTH:M:SZ
	Results       []ReportItem `json:"results"`
	ClusterName   string       `json:"cluster_name,omitempty"` // NOTE: The key here is ClusterName to match the Anchore API but it's actually the region
	InventoryType string       `json:"inventory_type"`
}
