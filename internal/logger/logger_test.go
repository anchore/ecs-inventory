package logger

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoggerInit(t *testing.T) {
	assert.Equal(t, Log, &NoOpLogger{})

	zapLogger := InitZapLogger(LogConfig{Level: "info", FileLocation: ""})

	assert.NotNil(t, zapLogger.zap)
}

func TestLogsToFileIfFileLocationProvided(t *testing.T) {
	tmpDir := t.TempDir()
	fileLocation := path.Join(tmpDir, "log")

	Log = InitZapLogger(LogConfig{Level: "info", FileLocation: fileLocation})

	expectedLogMsg := "test log foobar"
	Log.Info(expectedLogMsg)

	b, err := os.ReadFile(fileLocation)

	if (b == nil) || (err != nil) {
		t.Errorf("Expected log file to be created at %s", fileLocation)
	}

	assert.Contains(t, string(b), expectedLogMsg)
}

func TestLoggerDefaultsToInfoLevelOnInvalidLevel(t *testing.T) {
	zapLogger := InitZapLogger(LogConfig{Level: "invalid", FileLocation: ""})

	assert.Equal(t, zapLogger.zap.Level().String(), "info")
}
