// Package logrotate provides daily log rotation functionality for both
// standard library logging and zerolog.
package logrotate

import (
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
	"gopkg.in/natefinch/lumberjack.v2"
)

// StandardLogConfig holds configuration for standard library logger rotation
type StandardLogConfig struct {
	Filename   string // Log file path
	MaxSize    int    // Maximum size in megabytes before rotation (default: 100MB)
	MaxAge     int    // Maximum number of days to retain old log files (default: 30 days)
	MaxBackups int    // Maximum number of old log files to retain (default: 10)
	LocalTime  bool   // Use local time for backup file timestamps (default: false, uses UTC)
	Compress   bool   // Compress rotated files (default: false)
}

// ZerologConfig holds configuration for zerolog rotation
type ZerologConfig struct {
	Filename   string // Log file path
	MaxSize    int    // Maximum size in megabytes before rotation (default: 100MB)
	MaxAge     int    // Maximum number of days to retain old log files (default: 30 days)
	MaxBackups int    // Maximum number of old log files to retain (default: 10)
	LocalTime  bool   // Use local time for backup file timestamps (default: false, uses UTC)
	Compress   bool   // Compress rotated files (default: false)
}

// DefaultStandardLogConfig returns a default configuration for standard library logger
func DefaultStandardLogConfig(filename string) *StandardLogConfig {
	return &StandardLogConfig{
		Filename:   filename,
		MaxSize:    100, // 100MB
		MaxAge:     30,  // 3 days
		MaxBackups: 30,  // 10 backup files
		LocalTime:  true,
		Compress:   true,
	}
}

// DefaultZerologConfig returns a default configuration for zerolog
func DefaultZerologConfig(filename string) *ZerologConfig {
	return &ZerologConfig{
		Filename:   filename,
		MaxSize:    100, // 100MB
		MaxAge:     30,  // 3 days
		MaxBackups: 30,  // 10 backup files
		LocalTime:  true,
		Compress:   true,
	}
}

// CreateStandardLogger creates a logger that outputs to both file (with rotation) and console
func CreateStandardLogger(config *StandardLogConfig, prefix string, flag int) (*log.Logger, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(config.Filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	// Create lumberjack logger for file rotation
	fileLogger := &lumberjack.Logger{
		Filename:   config.Filename,
		MaxSize:    config.MaxSize,
		MaxAge:     config.MaxAge,
		MaxBackups: config.MaxBackups,
		LocalTime:  config.LocalTime,
		Compress:   config.Compress,
	}

	// Create multi-writer to output to both file and console
	multiWriter := io.MultiWriter(os.Stderr, fileLogger)

	// Create and return the logger
	return log.New(multiWriter, prefix, flag), nil
}

// CreateZerologLogger creates a zerolog logger that outputs to file with rotation
func CreateZerologLogger(config *ZerologConfig) (zerolog.Logger, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(config.Filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return zerolog.Logger{}, err
	}

	// Create lumberjack logger for file rotation
	fileLogger := &lumberjack.Logger{
		Filename:   config.Filename,
		MaxSize:    config.MaxSize,
		MaxAge:     config.MaxAge,
		MaxBackups: config.MaxBackups,
		LocalTime:  config.LocalTime,
		Compress:   config.Compress,
	}

	// Create zerolog logger with JSON output
	logger := zerolog.New(fileLogger)
	return logger, nil
}

// CreateZerologLoggerWithConsole creates a zerolog logger that outputs to both file (with rotation) and console
func CreateZerologLoggerWithConsole(config *ZerologConfig) (zerolog.Logger, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(config.Filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return zerolog.Logger{}, err
	}

	// Create lumberjack logger for file rotation
	fileLogger := &lumberjack.Logger{
		Filename:   config.Filename,
		MaxSize:    config.MaxSize,
		MaxAge:     config.MaxAge,
		MaxBackups: config.MaxBackups,
		LocalTime:  config.LocalTime,
		Compress:   config.Compress,
	}

	// Create console writer for pretty printing
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stderr}

	// Create multi-writer to output to both file and console
	multiWriter := io.MultiWriter(fileLogger, consoleWriter)

	// Create zerolog logger
	logger := zerolog.New(multiWriter)
	return logger, nil
}

// RotateFile manually triggers rotation for a given file
func RotateFile(filename string) error {
	logger := &lumberjack.Logger{Filename: filename}
	return logger.Rotate()
}
