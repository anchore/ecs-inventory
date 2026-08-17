// Handles exposing and determining application version details
package version

import (
	"fmt"
	"runtime"
)

// ValueNotProvided is the placeholder used for build values that were not
// injected at link time (i.e. a local, non-release build).
const ValueNotProvided = "[not provided]"

var (
	version        = ValueNotProvided
	gitCommit      = ValueNotProvided
	gitDescription = ValueNotProvided
	buildDate      = ValueNotProvided
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
