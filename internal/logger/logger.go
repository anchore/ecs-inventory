package logger

import (
	"log"

	"go.uber.org/zap"
)

type Logger struct {
	zap *zap.SugaredLogger
}

func (log Logger) Debug(msg string, args ...interface{}) {
	log.zap.Debugw(msg, args...)
}

func (log Logger) Info(msg string, args ...interface{}) {
	log.zap.Infow(msg, args...)
}

func (log Logger) Warn(msg string, args ...interface{}) {
	log.zap.Warnw(msg, args...)
}

func (log Logger) Error(msg string, err error, args ...interface{}) {
	args = append(args, "err", err)

	log.zap.Errorw(msg, args...)
}

type LogConfig struct {
	Level        string
	FileLocation string
}

var Log Logger

func InitLogger(logConfig LogConfig) {
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

	Log = Logger{
		zap: zap.Must(cfg.Build()).Sugar(),
	}
}
