package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/clwg/egress-tracer/pkg/cache"
	"github.com/clwg/egress-tracer/pkg/ebpf"
	"github.com/clwg/egress-tracer/pkg/filter"
	"github.com/clwg/egress-tracer/pkg/logger"
	"github.com/clwg/egress-tracer/pkg/output"
	"github.com/clwg/egress-tracer/pkg/theme"
	"github.com/clwg/egress-tracer/pkg/tui"
	"github.com/clwg/egress-tracer/pkg/types"
)

func main() {
	// Parse command line flags
	jsonOutput := flag.Bool("json", false, "Output events in JSON format")
	tuiMode := flag.Bool("tui", false, "Launch in TUI mode")
	cacheTTL := flag.Duration("cache-ttl", 5*time.Minute, "Process cache TTL duration")
	cacheMaxSize := flag.Int("cache-max-size", 1000, "Maximum number of entries in process cache")

	// TUI cache options
	tuiCacheMaxSize := flag.Int("tui-cache-max-size", 1000, "Maximum number of TUI connection entries before eviction")
	tuiCacheTTL := flag.Duration("tui-cache-ttl", 10*time.Minute, "TUI connection cache TTL duration")

	// Rotating log options
	logFile := flag.String("log-file", "", "Path to rotating log file (enables JSONL logging to file)")
	logMaxSize := flag.Int64("log-max-size", 100*1024*1024, "Maximum size of log file before rotation (bytes)")
	logMaxFiles := flag.Int("log-max-files", 5, "Maximum number of rotated log files to keep")

	// Process filter options
	filterFile := flag.String("filter", "", "Path to filter file containing SHA256 hashes (one per line)")

	// Theme options
	themeName := flag.String("theme", "dark", fmt.Sprintf("TUI theme (%s)", strings.Join(theme.GetAvailableThemes(), ", ")))

	flag.Parse()

	if *tuiMode {
		runTUI(*cacheTTL, *cacheMaxSize, *tuiCacheMaxSize, *tuiCacheTTL, *filterFile, *themeName)
		return
	}

	// Initialize process cache with LRU and TTL
	processCache := cache.NewProcessCache(*cacheTTL, *cacheMaxSize)

	// Load filter if specified
	if *filterFile != "" {
		if err := processCache.LoadFilterFromFile(*filterFile); err != nil {
			var fileNotExistErr *filter.FileNotExistError
			if errors.As(err, &fileNotExistErr) {
				log.Fatalf("Filter file does not exist: %s\nPlease create the file or use --filter=\"\" to disable filtering.", *filterFile)
			}
			log.Fatalf("Loading filter file: %v", err)
		}
		log.Printf("Loaded filter from %s (%d hashes)", *filterFile, processCache.GetProcessFilter().GetHashCount())
	}

	// Initialize rotating logger if log file is specified
	var rotatingLogger *logger.RotatingLogger
	if *logFile != "" {
		var err error
		rotatingLogger, err = logger.NewRotatingLogger(*logFile, *logMaxSize, *logMaxFiles)
		if err != nil {
			log.Fatalf("Creating rotating logger: %v", err)
		}
		defer rotatingLogger.Close()

		// Force JSON output when logging to file
		*jsonOutput = true

		log.Printf("Rotating JSONL logging enabled: %s (max size: %d bytes, max files: %d)",
			*logFile, *logMaxSize, *logMaxFiles)
	}

	// Create eBPF tracer
	tracer, err := ebpf.New()
	if err != nil {
		log.Fatalf("Creating eBPF tracer: %v", err)
	}
	defer tracer.Close()

	// Handle Ctrl+C
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Check if output is to terminal for formatting
	isTerminal := output.IsTerminal() && !*jsonOutput

	if isTerminal {
		fmt.Println("========== Egress Tracer ==========")
		fmt.Println("Tracking network connections... Press Ctrl+C to exit")
		fmt.Println()
	}

	// Start cache cleanup goroutine
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				processCache.CleanExpired()
			case <-stopper:
				return
			}
		}
	}()

	// Graceful shutdown goroutine
	go func() {
		<-stopper
		if err := tracer.Close(); err != nil {
			log.Printf("Error closing tracer: %v", err)
		}
		os.Exit(0)
	}()

	// Read events
	for {
		event, err := tracer.ReadEvent()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			continue
		}

		// Check if process is filtered (filtered out) by attempting to get process info
		// If GetProcessInfo returns nil, the process is filtered and should be dropped
		if processCache.GetProcessInfo(event.PID) == nil {
			continue // Drop the event silently
		}

		output.PrintEventWithLogger(event, isTerminal, *jsonOutput, processCache, rotatingLogger)
	}
}

func runTUI(cacheTTL time.Duration, cacheMaxSize int, tuiCacheMaxSize int, tuiCacheTTL time.Duration, filterFile string, themeName string) {
	// Validate and get theme
	selectedTheme, exists := theme.GetTheme(themeName)
	if !exists {
		log.Fatalf("Invalid theme '%s'. Available themes: %s", themeName, strings.Join(theme.GetAvailableThemes(), ", "))
	}
	// Initialize process cache with LRU and TTL
	processCache := cache.NewProcessCache(cacheTTL, cacheMaxSize)

	// Load filter if specified
	if filterFile != "" {
		if err := processCache.LoadFilterFromFile(filterFile); err != nil {
			var fileNotExistErr *filter.FileNotExistError
			if errors.As(err, &fileNotExistErr) {
				// Prompt user to create the file
				fmt.Printf("Filter file does not exist: %s\n", filterFile)
				fmt.Print("Would you like to create it? (y/N): ")
				
				var response string
				fmt.Scanln(&response)
				
				if strings.ToLower(strings.TrimSpace(response)) == "y" {
					if err := filter.CreateFilterFile(filterFile); err != nil {
						log.Fatalf("Failed to create filter file: %v", err)
					}
					fmt.Printf("Created filter file: %s\n", filterFile)
					// Load the newly created file
					if err := processCache.LoadFilterFromFile(filterFile); err != nil {
						log.Fatalf("Failed to load newly created filter file: %v", err)
					}
				} else {
					fmt.Println("Continuing without process filtering...")
					filterFile = "" // Disable filter
				}
			} else {
				log.Fatalf("Loading filter file: %v", err)
			}
		} else {
			log.Printf("Loaded filter from %s (%d hashes)", filterFile, processCache.GetProcessFilter().GetHashCount())
		}
	}

	// Create eBPF tracer
	tracer, err := ebpf.New()
	if err != nil {
		log.Fatalf("Creating eBPF tracer: %v", err)
	}
	defer tracer.Close()

	// Initialize TUI model with theme
	model := tui.NewModelWithCacheAndTheme(tuiCacheMaxSize, tuiCacheTTL, processCache, filterFile, selectedTheme)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		cancel()
	}()

	// Start cache cleanup goroutine
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				processCache.CleanExpired()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Start the TUI
	program := tea.NewProgram(&model, tea.WithAltScreen())

	// Event reader goroutine
	go func() {
		defer func() {
			program.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				event, err := tracer.ReadEvent()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					continue
				}

				// Check if process is filtered (filtered out)
				// If GetProcessInfo returns nil, the process is filtered and should be dropped
				if processCache.GetProcessInfo(event.PID) == nil {
					continue // Drop the event silently
				}

				// Convert ConnectionEvent to Event
				tuiEvent := convertToEvent(event, processCache)
				program.Send(tui.EventMsg{Event: tuiEvent})
			}
		}
	}()

	// Run the TUI
	if _, err := program.Run(); err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
		os.Exit(1)
	}
}

func convertToEvent(connEvent *types.ConnectionEvent, processCache *cache.ProcessCache) *types.Event {
	// Convert comm from C string
	comm := string(bytes.TrimRight((*(*[16]byte)(unsafe.Pointer(&connEvent.Comm[0])))[:], "\x00"))

	// Convert addresses
	dstIP := intToIP(connEvent.DstAddr)

	// Convert ports from network byte order
	dstPort := binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&connEvent.DstPort)))[:])

	protocol := "TCP"
	switch connEvent.Protocol {
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
	if procInfo := processCache.GetProcessInfo(connEvent.PID); procInfo != nil {
		processPath = procInfo.Path
		processHash = procInfo.SHA256
	}

	return &types.Event{
		Timestamp:     now.Format(time.RFC3339),
		Process:       comm,
		PID:           connEvent.PID,
		TGID:          connEvent.TGID,
		Protocol:      protocol,
		Destination:   dstIP,
		Port:          dstPort,
		ProcessPath:   processPath,
		ProcessSHA256: processHash,
	}
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
