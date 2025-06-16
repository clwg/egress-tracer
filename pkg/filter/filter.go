package filter

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FileNotExistError is returned when the filter file doesn't exist
type FileNotExistError struct {
	Path string
}

func (e *FileNotExistError) Error() string {
	return fmt.Sprintf("filter file does not exist: %s", e.Path)
}

// ProcessFilter manages SHA256 hashes for process filtering
type ProcessFilter struct {
	hashes map[string]bool
	mutex  sync.RWMutex
}

// NewProcessFilter creates a new process filter
func NewProcessFilter() *ProcessFilter {
	return &ProcessFilter{
		hashes: make(map[string]bool),
	}
}

// LoadFromFile loads SHA256 hashes from a file
// File format: one SHA256 hash per line, comments start with #
func (pf *ProcessFilter) LoadFromFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, return a special error that can be handled
			return &FileNotExistError{Path: filePath}
		}
		return fmt.Errorf("failed to open filter file: %w", err)
	}
	defer file.Close()

	pf.mutex.Lock()
	defer pf.mutex.Unlock()

	// Clear existing hashes
	pf.hashes = make(map[string]bool)

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Validate SHA256 format (64 hex characters)
		if len(line) != 64 {
			return fmt.Errorf("invalid SHA256 hash at line %d: %s (must be 64 hex characters)", lineNum, line)
		}

		// Validate hex characters
		for _, char := range line {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
				return fmt.Errorf("invalid SHA256 hash at line %d: %s (contains non-hex characters)", lineNum, line)
			}
		}

		// Convert to lowercase for consistent matching
		pf.hashes[strings.ToLower(line)] = true
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading filter file: %w", err)
	}

	return nil
}

// IsFiltered checks if a SHA256 hash is in the filter
func (pf *ProcessFilter) IsFiltered(sha256Hash string) bool {
	if sha256Hash == "" {
		return false
	}

	pf.mutex.RLock()
	defer pf.mutex.RUnlock()

	// Convert to lowercase for consistent matching
	return pf.hashes[strings.ToLower(sha256Hash)]
}

// AddHash adds a SHA256 hash to the filter
func (pf *ProcessFilter) AddHash(sha256Hash string) error {
	if len(sha256Hash) != 64 {
		return fmt.Errorf("invalid SHA256 hash: %s (must be 64 hex characters)", sha256Hash)
	}

	// Validate hex characters
	for _, char := range sha256Hash {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return fmt.Errorf("invalid SHA256 hash: %s (contains non-hex characters)", sha256Hash)
		}
	}

	pf.mutex.Lock()
	defer pf.mutex.Unlock()

	pf.hashes[strings.ToLower(sha256Hash)] = true
	return nil
}

// RemoveHash removes a SHA256 hash from the filter
func (pf *ProcessFilter) RemoveHash(sha256Hash string) {
	pf.mutex.Lock()
	defer pf.mutex.Unlock()

	delete(pf.hashes, strings.ToLower(sha256Hash))
}

// GetHashCount returns the number of hashes in the filter
func (pf *ProcessFilter) GetHashCount() int {
	pf.mutex.RLock()
	defer pf.mutex.RUnlock()

	return len(pf.hashes)
}

// GetAllHashes returns all hashes in the filter
func (pf *ProcessFilter) GetAllHashes() []string {
	pf.mutex.RLock()
	defer pf.mutex.RUnlock()

	hashes := make([]string, 0, len(pf.hashes))
	for hash := range pf.hashes {
		hashes = append(hashes, hash)
	}

	return hashes
}

// Clear removes all hashes from the filter
func (pf *ProcessFilter) Clear() {
	pf.mutex.Lock()
	defer pf.mutex.Unlock()

	pf.hashes = make(map[string]bool)
}

// ReloadFromFile reloads the filter from a file
func (pf *ProcessFilter) ReloadFromFile(filePath string) error {
	return pf.LoadFromFile(filePath)
}

// CreateFilterFile creates a new filter file with a default header
func CreateFilterFile(filePath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Create the file with default content
	content := `# Filter file for egress-tracer
# One SHA256 hash per line
# Lines starting with # are comments and will be ignored
# Empty lines are also ignored
`

	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to create filter file: %w", err)
	}

	return nil
}
