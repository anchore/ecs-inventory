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

func TestNoOpLoggerMethods(t *testing.T) {
	noop := &NoOpLogger{}

	// Verify none of the methods panic
	t.Run("Debug", func(t *testing.T) {
		noop.Debug("test message", "key", "value")
	})
	t.Run("Debugf", func(t *testing.T) {
		noop.Debugf("test %s", "message")
	})
	t.Run("Info", func(t *testing.T) {
		noop.Info("test message", "key", "value")
	})
	t.Run("Warn", func(t *testing.T) {
		noop.Warn("test message", "key", "value")
	})
	t.Run("Warnf", func(t *testing.T) {
		noop.Warnf("test %s", "message")
	})
	t.Run("Error", func(t *testing.T) {
		noop.Error("test message", assert.AnError, "key", "value")
	})
}

func TestZapLoggerMethods(t *testing.T) {
	tmpDir := t.TempDir()
	fileLocation := path.Join(tmpDir, "test.log")

	zapLogger := InitZapLogger(LogConfig{Level: "debug", FileLocation: fileLocation})

	t.Run("Debug", func(t *testing.T) {
		zapLogger.Debug("debug message", "key", "value")
	})
	t.Run("Debugf", func(t *testing.T) {
		zapLogger.Debugf("debugf %s", "message")
	})
	t.Run("Info", func(t *testing.T) {
		zapLogger.Info("info message", "key", "value")
	})
	t.Run("Warn", func(t *testing.T) {
		zapLogger.Warn("warn message", "key", "value")
	})
	t.Run("Warnf", func(t *testing.T) {
		zapLogger.Warnf("warnf %s", "message")
	})
	t.Run("Error", func(t *testing.T) {
		zapLogger.Error("error message", assert.AnError, "key", "value")
	})

	// Verify log file was written to
	b, err := os.ReadFile(fileLocation)
	assert.NoError(t, err)
	assert.Contains(t, string(b), "debug message")
	assert.Contains(t, string(b), "warn message")
	assert.Contains(t, string(b), "error message")
}
