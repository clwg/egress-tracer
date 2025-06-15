package filter

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

// WhitelistFilter manages SHA256 hashes for process filtering
type WhitelistFilter struct {
	hashes map[string]bool
	mutex  sync.RWMutex
}

// NewWhitelistFilter creates a new whitelist filter
func NewWhitelistFilter() *WhitelistFilter {
	return &WhitelistFilter{
		hashes: make(map[string]bool),
	}
}

// LoadFromFile loads SHA256 hashes from a file
// File format: one SHA256 hash per line, comments start with #
func (wf *WhitelistFilter) LoadFromFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open whitelist file: %w", err)
	}
	defer file.Close()

	wf.mutex.Lock()
	defer wf.mutex.Unlock()

	// Clear existing hashes
	wf.hashes = make(map[string]bool)

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
		wf.hashes[strings.ToLower(line)] = true
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading whitelist file: %w", err)
	}

	return nil
}

// IsWhitelisted checks if a SHA256 hash is in the whitelist
func (wf *WhitelistFilter) IsWhitelisted(sha256Hash string) bool {
	if sha256Hash == "" {
		return false
	}
	
	wf.mutex.RLock()
	defer wf.mutex.RUnlock()
	
	// Convert to lowercase for consistent matching
	return wf.hashes[strings.ToLower(sha256Hash)]
}

// AddHash adds a SHA256 hash to the whitelist
func (wf *WhitelistFilter) AddHash(sha256Hash string) error {
	if len(sha256Hash) != 64 {
		return fmt.Errorf("invalid SHA256 hash: %s (must be 64 hex characters)", sha256Hash)
	}
	
	// Validate hex characters
	for _, char := range sha256Hash {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return fmt.Errorf("invalid SHA256 hash: %s (contains non-hex characters)", sha256Hash)
		}
	}
	
	wf.mutex.Lock()
	defer wf.mutex.Unlock()
	
	wf.hashes[strings.ToLower(sha256Hash)] = true
	return nil
}

// RemoveHash removes a SHA256 hash from the whitelist
func (wf *WhitelistFilter) RemoveHash(sha256Hash string) {
	wf.mutex.Lock()
	defer wf.mutex.Unlock()
	
	delete(wf.hashes, strings.ToLower(sha256Hash))
}

// GetHashCount returns the number of hashes in the whitelist
func (wf *WhitelistFilter) GetHashCount() int {
	wf.mutex.RLock()
	defer wf.mutex.RUnlock()
	
	return len(wf.hashes)
}

// GetAllHashes returns all hashes in the whitelist
func (wf *WhitelistFilter) GetAllHashes() []string {
	wf.mutex.RLock()
	defer wf.mutex.RUnlock()
	
	hashes := make([]string, 0, len(wf.hashes))
	for hash := range wf.hashes {
		hashes = append(hashes, hash)
	}
	
	return hashes
}

// Clear removes all hashes from the whitelist
func (wf *WhitelistFilter) Clear() {
	wf.mutex.Lock()
	defer wf.mutex.Unlock()
	
	wf.hashes = make(map[string]bool)
}

// ReloadFromFile reloads the whitelist from a file
func (wf *WhitelistFilter) ReloadFromFile(filePath string) error {
	return wf.LoadFromFile(filePath)
}
