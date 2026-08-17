package version

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFromBuild(t *testing.T) {
	version := FromBuild()

	assert.Equal(t, ValueNotProvided, version.Version)
	assert.Equal(t, ValueNotProvided, version.GitCommit)
	assert.Equal(t, ValueNotProvided, version.BuildDate)
	assert.Equal(t, ValueNotProvided, version.GitDescription)
	assert.Equal(t, runtime.Version(), version.GoVersion)
	assert.Equal(t, runtime.Compiler, version.Compiler)
	assert.Equal(t, fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH), version.Platform)
}
