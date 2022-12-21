package inventory

type Report struct {
	Timestamp     string       `json:"timestamp,omitempty"` // Should be generated using time.Now.UTC() and formatted according to RFC Y-M-DTH:M:SZ
	Results       []ReportItem `json:"results"`
	InventoryType string       `json:"inventory_type"`
}
