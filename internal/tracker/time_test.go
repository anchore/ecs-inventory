package tracker

import (
	"testing"
	"time"

	"github.com/anchore/ecs-inventory/internal/logger"
)

func TestTrackFunctionTime(t *testing.T) {
	// Initialize the logger so the function can log without panicking
	logger.Log = logger.InitZapLogger(logger.LogConfig{Level: "debug", FileLocation: ""})

	t.Run("does not panic with current time", func(t *testing.T) {
		TrackFunctionTime(time.Now(), "test function")
	})

	t.Run("does not panic with past time", func(t *testing.T) {
		TrackFunctionTime(time.Now().Add(-5*time.Second), "past time test")
	})
}
