// Handles exposing and determining application version details
package version

import (
	"fmt"
	"runtime"
)

const valueNotProvided = "[not provided]"

var (
	version        = valueNotProvided
	gitCommit      = valueNotProvided
	gitDescription = valueNotProvided
	buildDate      = valueNotProvided
	platform       = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
)

type Version struct {
	Version        string `json:"version"`
	GitCommit      string `json:"gitCommit"`      // git SHA at build time
	GitDescription string `json:"gitDescription"` // output of 'git describe --dirty --always --tags'
	BuildDate      string `json:"buildDate"`
	GoVersion      string `json:"goVersion"`
	Compiler       string `json:"compiler"`
	Platform       string `json:"platform"`
}

// Return version object (created or not during build)
func FromBuild() Version {
	return Version{
		Version:        version,
		GitCommit:      gitCommit,
		GitDescription: gitDescription,
		BuildDate:      buildDate,
		GoVersion:      runtime.Version(),
		Compiler:       runtime.Compiler,
		Platform:       platform,
	}
}
