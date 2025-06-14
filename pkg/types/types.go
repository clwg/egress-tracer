package types

import "time"

// ConnectionEvent represents the data structure from eBPF
type ConnectionEvent struct {
	PID      uint32
	TGID     uint32
	SrcAddr  uint32
	DstAddr  uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Comm     [16]int8
}

// ProcessInfo contains cached process information
type ProcessInfo struct {
	Path     string
	SHA256   string
	CachedAt time.Time
}

// Event represents the JSON output format
type Event struct {
	Timestamp     string `json:"timestamp"`
	Process       string `json:"process"`
	PID           uint32 `json:"pid"`
	TGID          uint32 `json:"tgid"`
	Protocol      string `json:"protocol"`
	Destination   string `json:"destination"`
	Port          uint16 `json:"port"`
	ProcessPath   string `json:"process_path,omitempty"`
	ProcessSHA256 string `json:"process_sha256,omitempty"`
}
