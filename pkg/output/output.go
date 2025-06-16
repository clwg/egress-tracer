package output

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
	"unsafe"

	"github.com/clwg/egress-tracer/pkg/cache"
	"github.com/clwg/egress-tracer/pkg/logger"
	"github.com/clwg/egress-tracer/pkg/types"
)

// PrintEvent formats and prints a connection event based on output configuration
func PrintEvent(event *types.ConnectionEvent, isTerminal, jsonOutput bool, processCache *cache.ProcessCache) {
	PrintEventWithLogger(event, isTerminal, jsonOutput, processCache, nil)
}

// PrintEventWithLogger formats and prints a connection event with optional rotating logger
func PrintEventWithLogger(event *types.ConnectionEvent, isTerminal, jsonOutput bool, processCache *cache.ProcessCache, rotatingLogger *logger.RotatingLogger) {
	// Convert comm from C string
	comm := string(bytes.TrimRight((*(*[16]byte)(unsafe.Pointer(&event.Comm[0])))[:], "\x00"))

	// Convert addresses
	dstIP := intToIP(event.DstAddr)

	// Convert ports from network byte order
	dstPort := binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&event.DstPort)))[:])

	// Check for read errors and add warning
	var errorWarning string
	if event.Flags != 0 {
		var errors []string
		if event.Flags&types.FLAG_ADDR_READ_FAILED != 0 {
			errors = append(errors, "addr_read_failed")
		}
		if event.Flags&types.FLAG_PORT_READ_FAILED != 0 {
			errors = append(errors, "port_read_failed")
		}
		if event.Flags&types.FLAG_FAMILY_READ_FAILED != 0 {
			errors = append(errors, "family_read_failed")
		}
		if len(errors) > 0 {
			errorWarning = fmt.Sprintf(" [eBPF_errors: %v]", errors)
		}
	}

	protocol := "TCP"
	switch event.Protocol {
	case 1: // IPPROTO_ICMP
		protocol = "ICMP"
	case 17: // IPPROTO_UDP
		protocol = "UDP"
	default:
		protocol = "TCP"
	}

	now := time.Now()

	// Get process information
	var processPath, processHash string
	if procInfo := processCache.GetProcessInfo(event.PID); procInfo != nil {
		processPath = procInfo.Path
		processHash = procInfo.SHA256
	}

	if jsonOutput {
		printJSONEvent(now, comm, event, protocol, dstIP, dstPort, processPath, processHash, errorWarning, rotatingLogger)
	} else if isTerminal {
		printTerminalEvent(now, comm, event, protocol, dstIP, dstPort, processPath, processHash, errorWarning)
	} else {
		printPipeEvent(now, comm, event, protocol, dstIP, dstPort, processPath, processHash, errorWarning)
	}
}

// printJSONEvent outputs event in JSON format
func printJSONEvent(now time.Time, comm string, event *types.ConnectionEvent, protocol, dstIP string, dstPort uint16, processPath, processHash, errorWarning string, rotatingLogger *logger.RotatingLogger) {
	evt := types.Event{
		Timestamp:     now.Format(time.RFC3339),
		Process:       comm,
		PID:           event.PID,
		TGID:          event.TGID,
		Protocol:      protocol,
		Destination:   dstIP,
		Port:          dstPort,
		ProcessPath:   processPath,
		ProcessSHA256: processHash,
		Errors:        errorWarning,
	}
	if data, err := json.Marshal(evt); err == nil {
		if rotatingLogger != nil {
			// Write to rotating log file
			if err := rotatingLogger.Write(data); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing to rotating log: %v\n", err)
			}
		} else {
			// Write to stdout
			fmt.Println(string(data))
		}
	}
}

// printTerminalEvent outputs colored terminal event
func printTerminalEvent(now time.Time, comm string, event *types.ConnectionEvent, protocol, dstIP string, dstPort uint16, processPath, processHash, errorWarning string) {
	if processPath != "" && processHash != "" {
		fmt.Printf("[%s] \033[1;36m%-12s\033[0m TGID:\033[1;33m%d\033[0m PID:\033[1;33m%d\033[0m \033[1;32m%s\033[0m → \033[1;35m%s:%d\033[0m Path:\033[1;34m%s\033[0m Hash:\033[1;90m%s\033[0m%s\n",
			now.Format("15:04:05"), comm, event.TGID, event.PID, protocol, dstIP, dstPort, processPath, processHash, errorWarning)
	} else if processPath != "" {
		fmt.Printf("[%s] \033[1;36m%-12s\033[0m TGID:\033[1;33m%d\033[0m PID:\033[1;33m%d\033[0m \033[1;32m%s\033[0m → \033[1;35m%s:%d\033[0m Path:\033[1;34m%s\033[0m%s\n",
			now.Format("15:04:05"), comm, event.TGID, event.PID, protocol, dstIP, dstPort, processPath, errorWarning)
	} else {
		fmt.Printf("[%s] \033[1;36m%-12s\033[0m TGID:\033[1;33m%d\033[0m PID:\033[1;33m%d\033[0m \033[1;32m%s\033[0m → \033[1;35m%s:%d\033[0m%s\n",
			now.Format("15:04:05"), comm, event.TGID, event.PID, protocol, dstIP, dstPort, errorWarning)
	}
}

// printPipeEvent outputs machine-parsable pipe-delimited event
func printPipeEvent(now time.Time, comm string, event *types.ConnectionEvent, protocol, dstIP string, dstPort uint16, processPath, processHash, errorWarning string) {
	fmt.Printf("%s|%s|%d|%d|%s|%s|%d|%s|%s|%s\n",
		now.Format("2006-01-02 15:04:05"), comm, event.PID, event.TGID, protocol, dstIP, dstPort, processPath, processHash, errorWarning)
}

// intToIP converts a uint32 IP address to string
func intToIP(addr uint32) string {
	return net.IPv4(
		byte(addr),
		byte(addr>>8),
		byte(addr>>16),
		byte(addr>>24),
	).String()
}

// IsTerminal checks if stdout is a terminal
func IsTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
