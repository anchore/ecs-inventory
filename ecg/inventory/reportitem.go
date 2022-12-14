package inventory

import (
	"fmt"
)

// ReportItem represents a namespace and all it's unique images
type ReportItem struct {
	Namespace string        `json:"namespace,omitempty"`
	Images    []ReportImage `json:"images"`
}

// ReportImage represents a unique image in a cluster
type ReportImage struct {
	Tag        string `json:"tag,omitempty"`
	RepoDigest string `json:"repoDigest,omitempty"`
}

// String represent the ReportItem as a string
func (r *ReportItem) String() string {
	return fmt.Sprintf("ReportItem(namespace=%s, images=%v)", r.Namespace, r.Images)
}

// key will return a unique key for a ReportImage
func (i *ReportImage) key() string {
	return fmt.Sprintf("%s@%s", i.Tag, i.RepoDigest)
}
