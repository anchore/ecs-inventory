package logger

import (
	"log"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/anchore/ecs-inventory/pkg/logger"
)

type NoOpLogger struct{}

func (log NoOpLogger) Debug(msg string, args ...interface{}) {}

func (log NoOpLogger) Debugf(msg string, args ...interface{}) {}

func (log NoOpLogger) Info(msg string, args ...interface{}) {}

func (log NoOpLogger) Warn(msg string, args ...interface{}) {}

func (log NoOpLogger) Error(msg string, err error, args ...interface{}) {}

type ZapLogger struct {
	zap *zap.SugaredLogger
}

func (log ZapLogger) Debug(msg string, args ...interface{}) {
	log.zap.Debugw(msg, args...)
}

func (log ZapLogger) Debugf(msg string, args ...interface{}) {
	log.zap.Debugf(msg, args...)
}

func (log ZapLogger) Info(msg string, args ...interface{}) {
	log.zap.Infow(msg, args...)
}

func (log ZapLogger) Warn(msg string, args ...interface{}) {
	log.zap.Warnw(msg, args...)
}

func (log ZapLogger) Error(msg string, err error, args ...interface{}) {
	args = append(args, "err", err)

	log.zap.Errorw(msg, args...)
}

type LogConfig struct {
	Level        string
	FileLocation string
}

var Log logger.Logger = &NoOpLogger{}

func InitZapLogger(logConfig LogConfig) *ZapLogger {
	var cfg zap.Config

	level, err := zap.ParseAtomicLevel(logConfig.Level)
	if err != nil {
		log.Printf("Invalid log level: %s, defaulting to `info`", logConfig.Level)
		level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	if logConfig.FileLocation != "" {
		cfg = zap.Config{
			Level:         level,
			Encoding:      "json",
			EncoderConfig: zap.NewProductionEncoderConfig(),
			OutputPaths:   []string{logConfig.FileLocation},
		}
	} else {
		zapEncoderCfg := zap.NewProductionEncoderConfig()
		zapEncoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

		cfg = zap.Config{
			Level:            level,
			Encoding:         "console",
			EncoderConfig:    zapEncoderCfg,
			OutputPaths:      []string{"stdout"},
			ErrorOutputPaths: []string{"stderr"},
		}
	}

	return &ZapLogger{
		zap: zap.Must(cfg.Build()).Sugar(),
	}
}
