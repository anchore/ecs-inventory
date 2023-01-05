package logger

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoggerInit(t *testing.T) {
	assert.Nil(t, Log.zap)

	InitLogger(LogConfig{Level: "info", FileLocation: ""})

	assert.NotNil(t, Log.zap)
}

func TestLogsToFileIfFileLocationProvided(t *testing.T) {
	tmpDir := t.TempDir()
	fileLocation := path.Join(tmpDir, "log")

	InitLogger(LogConfig{Level: "info", FileLocation: fileLocation})

	var expectedLogMsg = "test log foobar"
	Log.Info(expectedLogMsg)

	b, err := os.ReadFile(fileLocation)

	if (b == nil) || (err != nil) {
		t.Errorf("Expected log file to be created at %s", fileLocation)
	}

	assert.Contains(t, string(b), expectedLogMsg)
}

func TestLoggerDefaultsToInfoLevelOnInvalidLevel(t *testing.T) {
	InitLogger(LogConfig{Level: "invalid", FileLocation: ""})

	assert.Equal(t, Log.zap.Level().String(), "info")
}
