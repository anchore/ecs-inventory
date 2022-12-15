package inventory

import (
	"fmt"
)

// ReportItem represents a cluster and all it's unique images
type ReportItem struct {
	Cluster string        `json:"cluster,omitempty"`
	Images  []ReportImage `json:"images"`
}

// ReportImage represents a unique image in a cluster
type ReportImage struct {
	Tag        string `json:"tag,omitempty"`
	RepoDigest string `json:"repoDigest,omitempty"`
}

// String represent the ReportItem as a string
func (r *ReportItem) String() string {
	return fmt.Sprintf("ReportItem(cluster=%s, images=%v)", r.Cluster, r.Images)
}

// key will return a unique key for a ReportImage
func (i *ReportImage) key() string {
	return fmt.Sprintf("%s@%s", i.Tag, i.RepoDigest)
}
