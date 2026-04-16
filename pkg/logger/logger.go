package logger

type Logger interface {
	Error(msg string, err error, args ...interface{})
	Errorf(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Warnf(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Infof(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Debugf(msg string, args ...interface{})
}
