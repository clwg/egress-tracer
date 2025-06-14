package logger

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// RotatingLogger handles rotating JSON Lines logging
type RotatingLogger struct {
	basePath    string
	maxSize     int64 // Maximum size in bytes before rotation
	maxFiles    int   // Maximum number of rotated files to keep
	currentFile *os.File
	currentSize int64
	writer      *bufio.Writer
	mutex       sync.Mutex
}

// NewRotatingLogger creates a new rotating logger
func NewRotatingLogger(basePath string, maxSize int64, maxFiles int) (*RotatingLogger, error) {
	rl := &RotatingLogger{
		basePath: basePath,
		maxSize:  maxSize,
		maxFiles: maxFiles,
	}

	if err := rl.openCurrentFile(); err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return rl, nil
}

// Write writes a JSON line to the log file
func (rl *RotatingLogger) Write(data []byte) error {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	// Check if we need to rotate
	if rl.currentSize+int64(len(data))+1 > rl.maxSize { // +1 for newline
		if err := rl.rotate(); err != nil {
			return fmt.Errorf("failed to rotate log: %w", err)
		}
	}

	// Write the data with newline
	n, err := rl.writer.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write to log: %w", err)
	}

	// Add newline for JSONL format
	if _, err := rl.writer.WriteString("\n"); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}

	rl.currentSize += int64(n) + 1

	// Flush the buffer
	if err := rl.writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush buffer: %w", err)
	}

	return nil
}

// Close closes the current log file
func (rl *RotatingLogger) Close() error {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	if rl.writer != nil {
		rl.writer.Flush()
	}

	if rl.currentFile != nil {
		return rl.currentFile.Close()
	}

	return nil
}

// openCurrentFile opens the current log file
func (rl *RotatingLogger) openCurrentFile() error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(rl.basePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open file for append, create if doesn't exist
	file, err := os.OpenFile(rl.basePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	// Get current file size
	fileInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("failed to stat log file: %w", err)
	}

	rl.currentFile = file
	rl.currentSize = fileInfo.Size()
	rl.writer = bufio.NewWriter(file)

	return nil
}

// rotate rotates the current log file
func (rl *RotatingLogger) rotate() error {
	// Close current file
	if rl.writer != nil {
		rl.writer.Flush()
	}
	if rl.currentFile != nil {
		rl.currentFile.Close()
	}

	// Rotate existing files
	if err := rl.rotateFiles(); err != nil {
		return fmt.Errorf("failed to rotate files: %w", err)
	}

	// Open new current file
	if err := rl.openCurrentFile(); err != nil {
		return fmt.Errorf("failed to open new log file: %w", err)
	}

	return nil
}

// rotateFiles handles the file rotation logic
func (rl *RotatingLogger) rotateFiles() error {
	// Remove the oldest file if we're at the limit
	oldestFile := fmt.Sprintf("%s.%d", rl.basePath, rl.maxFiles)
	if _, err := os.Stat(oldestFile); err == nil {
		if err := os.Remove(oldestFile); err != nil {
			return fmt.Errorf("failed to remove oldest log file: %w", err)
		}
	}

	// Rename existing files (move them up one number)
	for i := rl.maxFiles; i > 1; i-- {
		oldName := fmt.Sprintf("%s.%d", rl.basePath, i-1)
		newName := fmt.Sprintf("%s.%d", rl.basePath, i)

		if _, err := os.Stat(oldName); err == nil {
			if err := os.Rename(oldName, newName); err != nil {
				return fmt.Errorf("failed to rename log file %s to %s: %w", oldName, newName, err)
			}
		}
	}

	// Rename current file to .1
	rotatedName := fmt.Sprintf("%s.1", rl.basePath)
	if err := os.Rename(rl.basePath, rotatedName); err != nil {
		return fmt.Errorf("failed to rotate current log file: %w", err)
	}

	return nil
}

// GetCurrentFilePath returns the path to the current log file
func (rl *RotatingLogger) GetCurrentFilePath() string {
	return rl.basePath
}

// GetRotatedFilePaths returns paths to all rotated log files
func (rl *RotatingLogger) GetRotatedFilePaths() []string {
	var paths []string
	for i := 1; i <= rl.maxFiles; i++ {
		path := fmt.Sprintf("%s.%d", rl.basePath, i)
		if _, err := os.Stat(path); err == nil {
			paths = append(paths, path)
		}
	}
	return paths
}

// WriteTo writes to any io.Writer (for testing or alternative outputs)
func (rl *RotatingLogger) WriteTo(w io.Writer, data []byte) error {
	_, err := w.Write(data)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}
