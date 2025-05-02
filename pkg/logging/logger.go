package logging

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/zvdy/go-binwatch/pkg/audit"
)

// Logger provides secure logging capabilities
type Logger struct {
	logPath    string
	logFile    *os.File
	logger     *log.Logger
	mutex      sync.Mutex
	immutable  bool // Controls if logs can be modified
	appendOnly bool // Controls if logs can only be appended to
}

// NewLogger creates a new logger instance
func NewLogger(logPath string, immutable bool) (*Logger, error) {
	// Ensure directory exists
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file (create if not exists, append mode)
	flags := os.O_APPEND | os.O_CREATE | os.O_WRONLY
	mode := os.FileMode(0640) // rw-r-----

	logFile, err := os.OpenFile(logPath, flags, mode)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	logger := &Logger{
		logPath:    logPath,
		logFile:    logFile,
		logger:     log.New(logFile, "", log.Ldate|log.Ltime|log.LUTC),
		immutable:  immutable,
		appendOnly: true,
	}

	// Log startup
	logger.Info("BinWatch Logger initialized")
	return logger, nil
}

// Close closes the logger
func (l *Logger) Close() error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// Info logs an informational message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log("INFO", format, args...)
}

// Warning logs a warning message
func (l *Logger) Warning(format string, args ...interface{}) {
	l.log("WARNING", format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log("ERROR", format, args...)
}

// Audit logs an audit event (high security)
func (l *Logger) Audit(format string, args ...interface{}) {
	l.log("AUDIT", format, args...)

	// For audit events, also log to the system log
	if len(args) > 0 {
		message := fmt.Sprintf(format, args...)
		cmd := fmt.Sprintf("logger -p auth.notice -t binwatch '%s'", message)
		exec.Command("sh", "-c", cmd).Run()
	} else {
		cmd := fmt.Sprintf("logger -p auth.notice -t binwatch '%s'", format)
		exec.Command("sh", "-c", cmd).Run()
	}
}

// log implements the core logging functionality
func (l *Logger) log(level, format string, args ...interface{}) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.logger == nil {
		return
	}

	// Format: [LEVEL] message
	if len(args) > 0 {
		l.logger.Printf("[%s] %s", level, fmt.Sprintf(format, args...))
	} else {
		l.logger.Printf("[%s] %s", level, format)
	}
}

// LogChange logs information about a binary change
func (l *Logger) LogChange(change *audit.Change) {
	path := change.Binary.Path

	switch change.ChangeType {
	case "added":
		l.Audit("New binary added: %s, SHA256: %s, Owner: %s, Permissions: %s",
			path, change.Binary.SHA256Hash, change.Binary.Owner, change.Binary.Permissions)
	case "deleted":
		l.Audit("Binary removed: %s", path)
	case "modified_content":
		l.Audit("Binary content modified: %s, Old hash: %s, New hash: %s",
			path, change.OldValue, change.NewValue)
	case "modified_permissions":
		l.Audit("Binary permissions modified: %s, Old: %s, New: %s",
			path, change.OldValue, change.NewValue)
	case "modified_owner":
		l.Audit("Binary owner modified: %s, Old: %s, New: %s",
			path, change.OldValue, change.NewValue)
	default:
		l.Audit("Binary change detected: %s, Type: %s", path, change.ChangeType)
	}
}

// LogChanges logs multiple binary changes
func (l *Logger) LogChanges(changes []*audit.Change) {
	if len(changes) == 0 {
		l.Info("No binary changes detected")
		return
	}

	l.Audit("Detected %d binary changes", len(changes))
	for _, change := range changes {
		l.LogChange(change)
	}
}

// GetLogSummary returns a summary of log statistics
func (l *Logger) GetLogSummary() map[string]interface{} {
	// Get file info
	info, err := l.logFile.Stat()
	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	return map[string]interface{}{
		"path":          l.logPath,
		"size_bytes":    info.Size(),
		"last_modified": info.ModTime(),
		"immutable":     l.immutable,
		"append_only":   l.appendOnly,
	}
}

// SetImmutable attempts to make the log file immutable
// using chattr +a (append only) Linux attribute
func (l *Logger) SetImmutable() error {
	// Can't set immutability on a non-immutable logger
	if !l.immutable {
		return fmt.Errorf("logger not configured for immutability")
	}

	// Make log append-only using chattr +a
	cmd := exec.Command("chattr", "+a", l.logPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set log as append-only: %w", err)
	}

	l.appendOnly = true
	l.Audit("Log file set as append-only (immutable)")
	return nil
}

// RotateLog rotates the current log file if it's too large
func (l *Logger) RotateLog(maxSizeMB int) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Check if log rotation is needed
	info, err := l.logFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat log file: %w", err)
	}

	// Convert MB to bytes
	maxSize := int64(maxSizeMB) * 1024 * 1024

	// If file is smaller than max size, no rotation needed
	if info.Size() < maxSize {
		return nil
	}

	// Close current log file
	if err := l.logFile.Close(); err != nil {
		return fmt.Errorf("failed to close log file: %w", err)
	}

	// Rotate log: logfile -> logfile.1
	timestamp := time.Now().UTC().Format("20060102-150405")
	newPath := fmt.Sprintf("%s.%s", l.logPath, timestamp)

	// If log is immutable, try to remove immutability first
	if l.appendOnly {
		cmd := exec.Command("chattr", "-a", l.logPath)
		if err := cmd.Run(); err != nil {
			// Fallback: Try to continue anyway
			l.appendOnly = false
		}
	}

	// Rename current log to timestamped version
	if err := os.Rename(l.logPath, newPath); err != nil {
		return fmt.Errorf("failed to rename log file: %w", err)
	}

	// Open new log file
	logFile, err := os.OpenFile(l.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("failed to create new log file: %w", err)
	}

	// Update logger
	l.logFile = logFile
	l.logger = log.New(logFile, "", log.Ldate|log.Ltime|log.LUTC)

	// Log rotation event
	l.Audit("Log rotated, previous log saved as %s", newPath)

	// Re-apply immutability if needed
	if l.immutable {
		return l.SetImmutable()
	}

	return nil
}
