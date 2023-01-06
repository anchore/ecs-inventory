package version

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFromBuild(t *testing.T) {
	version := FromBuild()

	assert.Equal(t, valueNotProvided, version.Version)
	assert.Equal(t, valueNotProvided, version.GitCommit)
	assert.Equal(t, valueNotProvided, version.BuildDate)
	assert.Equal(t, valueNotProvided, version.GitTreeState)
	assert.Equal(t, runtime.Version(), version.GoVersion)
	assert.Equal(t, runtime.Compiler, version.Compiler)
	assert.Equal(t, fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH), version.Platform)
}
