package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/ecs-inventory/pkg/logger"
)

type mockLogger struct{}

func (m *mockLogger) Error(msg string, err error, args ...interface{}) {}
func (m *mockLogger) Warn(msg string, args ...interface{})             {}
func (m *mockLogger) Warnf(msg string, args ...interface{})            {}
func (m *mockLogger) Info(msg string, args ...interface{})             {}
func (m *mockLogger) Debug(msg string, args ...interface{})            {}
func (m *mockLogger) Debugf(msg string, args ...interface{})           {}

func TestSetLogger(t *testing.T) {
	mock := &mockLogger{}
	SetLogger(mock)
	assert.Equal(t, logger.Logger(mock), log)
}
