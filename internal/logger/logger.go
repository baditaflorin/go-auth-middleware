package logger

import (
	"context"
	"io"
	"os"

	"github.com/rs/zerolog"
)

// Logger wraps zerolog for structured logging
type Logger struct {
	zlog zerolog.Logger
}

// New creates a new logger with the specified level and format
func New(level, format string, output io.Writer) *Logger {
	if output == nil {
		output = os.Stdout
	}

	// Parse level
	zLevel := zerolog.InfoLevel
	switch level {
	case "debug":
		zLevel = zerolog.DebugLevel
	case "info":
		zLevel = zerolog.InfoLevel
	case "warn":
		zLevel = zerolog.WarnLevel
	case "error":
		zLevel = zerolog.ErrorLevel
	}

	// Configure output format
	var zlog zerolog.Logger
	if format == "text" {
		zlog = zerolog.New(zerolog.ConsoleWriter{Out: output}).
			Level(zLevel).
			With().
			Timestamp().
			Logger()
	} else {
		zlog = zerolog.New(output).
			Level(zLevel).
			With().
			Timestamp().
			Logger()
	}

	return &Logger{zlog: zlog}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields map[string]interface{}) {
	event := l.zlog.Debug()
	for k, v := range fields {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

// Info logs an info message
func (l *Logger) Info(msg string, fields map[string]interface{}) {
	event := l.zlog.Info()
	for k, v := range fields {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields map[string]interface{}) {
	event := l.zlog.Warn()
	for k, v := range fields {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

// Error logs an error message
func (l *Logger) Error(msg string, err error, fields map[string]interface{}) {
	event := l.zlog.Error()
	if err != nil {
		event = event.Err(err)
	}
	for k, v := range fields {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

// WithContext returns a logger with context
func (l *Logger) WithContext(ctx context.Context) *Logger {
	return &Logger{zlog: l.zlog.With().Ctx(ctx).Logger()}
}

// WithFields returns a logger with additional fields
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	zlog := l.zlog.With()
	for k, v := range fields {
		zlog = zlog.Interface(k, v)
	}
	return &Logger{zlog: zlog.Logger()}
}

// Noop returns a no-op logger for testing
func Noop() *Logger {
	return &Logger{zlog: zerolog.Nop()}
}
