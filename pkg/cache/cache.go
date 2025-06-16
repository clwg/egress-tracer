package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/clwg/egress-tracer/pkg/filter"
	"github.com/clwg/egress-tracer/pkg/types"
	lru "github.com/hashicorp/golang-lru/v2/expirable"
)

// ProcessCache manages cached process information with LRU eviction
type ProcessCache struct {
	cache           *lru.LRU[uint32, *types.ProcessInfo]
	ttl             time.Duration
	processFilter *filter.ProcessFilter
}

// NewProcessCache creates a new process cache with the specified TTL and max size
func NewProcessCache(ttl time.Duration, maxSize int) *ProcessCache {
	cache := lru.NewLRU[uint32, *types.ProcessInfo](maxSize, nil, ttl)
	return &ProcessCache{
		cache:           cache,
		ttl:             ttl,
		processFilter: filter.NewProcessFilter(),
	}
}

// NewProcessCacheWithFilter creates a new process cache with a process filter
func NewProcessCacheWithFilter(ttl time.Duration, maxSize int, processFilter *filter.ProcessFilter) *ProcessCache {
	cache := lru.NewLRU[uint32, *types.ProcessInfo](maxSize, nil, ttl)
	return &ProcessCache{
		cache:           cache,
		ttl:             ttl,
		processFilter: processFilter,
	}
}

// GetProcessInfo retrieves process information for a PID, caching it if not present
// Returns nil if the process is filtered (should be filtered out)
func (pc *ProcessCache) GetProcessInfo(pid uint32) *types.ProcessInfo {
	// Check if we have cached info
	if info, ok := pc.cache.Get(pid); ok {
		// If it's filtered, return nil to indicate it should be filtered
		if pc.processFilter.IsFiltered(info.SHA256) {
			return nil
		}
		return info
	}

	// Fetch new process info
	newInfo := pc.fetchProcessInfo(pid)
	if newInfo != nil {
		// Check if the process is filtered before caching
		if pc.processFilter.IsFiltered(newInfo.SHA256) {
			// Still cache it, but return nil to indicate filtering
			pc.cache.Add(pid, newInfo)
			return nil
		}
		pc.cache.Add(pid, newInfo)
	}

	return newInfo
}

// fetchProcessInfo retrieves process information from the filesystem
func (pc *ProcessCache) fetchProcessInfo(pid uint32) *types.ProcessInfo {
	procPath := fmt.Sprintf("/proc/%d/exe", pid)

	exePath, err := os.Readlink(procPath)
	if err != nil {
		return nil
	}

	hash, err := pc.calculateSHA256(exePath)
	if err != nil {
		return nil
	}

	return &types.ProcessInfo{
		Path:     exePath,
		SHA256:   hash,
		CachedAt: time.Now(),
	}
}

// calculateSHA256 computes the SHA256 hash of a file
func (pc *ProcessCache) calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// CleanExpired removes expired entries from the cache (handled automatically by LRU)
func (pc *ProcessCache) CleanExpired() {
	// Expirable LRU handles TTL automatically, no manual cleanup needed
}

// GetProcessFilter returns the process filter for runtime management
func (pc *ProcessCache) GetProcessFilter() *filter.ProcessFilter {
	return pc.processFilter
}

// LoadFilterFromFile loads filter from a file
func (pc *ProcessCache) LoadFilterFromFile(filePath string) error {
	return pc.processFilter.LoadFromFile(filePath)
}
