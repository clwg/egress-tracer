# Egress Tracer

A lightweight eBPF-based network connection tracer that monitors outbound TCP and UDP connections in real-time with process context and caching.


### Quickstart (Ubuntu 24.04)

Install required dependencies:

```bash
sudo apt install -y \
  make \
  golang \
  llvm \
  clang \
  linux-headers-$(uname -r) \
  libbpf-dev
```

## Build

```bash
make clean && make build && ./egress-tracer -h
```

## Usage (requires root privileges)

```bash
# Terminal User Interface (TUI) mode
sudo ./egress-tracer --tui

# TUI with theme selection (available themes: dark, light, monochrome, blue, rainbow)
sudo ./egress-tracer --tui --theme light

# TUI with a whitelist and removing connections from view after 30 seconds
sudo ./egress-tracer -whitelist whitelist.txt -tui -tui-cache-ttl 30s
```

# Options for CLI mode
```bash
sudo ./egress-tracer --json                    # JSON output
```
# Whitelist filtering (suppress output for specific processes)
```bash
sudo ./egress-tracer --whitelist=whitelist.txt # Load SHA256 whitelist from file
```


# Rotating JSONL Logging
```bash
sudo ./egress-tracer --log-file=/var/log/egress-tracer.jsonl          # Enable rotating JSONL logging

sudo ./egress-tracer --log-file=/var/log/egress-tracer.jsonl \
                    --log-max-size=52428800 \                  # Max file size before rotation (50MB)
                    --log-max-files=10                         # Max number of rotated files
```

# Process Cache which offloads /proc lookups
```bash
sudo ./egress-tracer --cache-ttl=10m           # PID Cache TTL
sudo ./egress-tracer --cache-max-size=500      # PID Cache size
```

## Whitelist Filtering

The whitelist feature allows you to suppress output for specific processes based on their SHA256 hash. Whitelist entries can be loaded from a file at startup or added interactively via the TUI.

### Interactive TUI Management

In TUI mode with `--whitelist` parameter, press `w` on any connection to add its process to the whitelist: **Requires starting with `--whitelist=filename`**. Changes are saved to the specified whitelist file and take effect immediately.

### Whitelist File Format

Create a text file with one SHA256 hash per line:

```
# Whitelist file for egress-tracer
# Lines starting with # are comments
# Empty lines are ignored

d4f7c9e8a1b2c3d4e5f6789012345678901234567890123456789012345678901234
a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890123
```

### Usage Examples

```bash
# CLI mode with whitelist
sudo ./egress-tracer --whitelist=trusted_processes.txt

# TUI mode with whitelist (enables interactive 'w' key - requires --whitelist parameter)
sudo ./egress-tracer --tui --whitelist=trusted_processes.txt

# JSON logging with whitelist
sudo ./egress-tracer --json --whitelist=trusted_processes.txt --log-file=events.jsonl
```

**Note**: If the whitelist file doesn't exist, you'll be prompted to create it automatically.

## TUI Theme Usage Examples

Some basic theme are available for the TUI interface.

```bash
# Use light theme (great for white terminal backgrounds)
sudo ./egress-tracer --tui --theme light

# Use monochrome theme (minimal, professional)
sudo ./egress-tracer --tui --theme monochrome

# Use rainbow theme (colorful and fun)
sudo ./egress-tracer --tui --theme rainbow

# Use blue theme
sudo ./egress-tracer --tui --theme blue

# Default dark theme (no flag needed)
sudo ./egress-tracer --tui
```


## Project Structure

```
.
├── Makefile                    # Build automation and development workflow
├── README.md                   # Project documentation
├── go.mod                      # Go module dependencies
├── go.sum                      # Go module checksums
├── bpf/                        # eBPF programs (kernel space)
│   └── tracer.bpf.c           # eBPF program for network connection tracing
├── cmd/                        # Application entry points
│   └── procnet/               # Main command-line application
│       └── main.go            # Application entry point with CLI parsing
└── pkg/                        # Reusable Go packages (user space)
    ├── cache/                  # Process information caching
    │   └── cache.go           # PID-to-process name cache implementation
    ├── ebpf/                   # eBPF program management
    │   └── ebpf.go            # eBPF loader, event processor, and program lifecycle
    ├── filter/                 # Process filtering and whitelist management
    │   └── whitelist.go       # SHA256-based process whitelist filtering
    ├── logger/                 # Rotating JSON Lines logging
    │   └── rotating.go        # Rotating log file implementation with size-based rotation
    ├── output/                 # Event formatting and output
    │   └── output.go          # Connection event formatting (JSON/text/JSONL)
    ├── theme/                  # TUI theme system
    │   └── theme.go           # Color theme definitions and management
    ├── tui/                    # Terminal User Interface
    │   └── model.go           # Interactive TUI with real-time connection monitoring
    └── types/                  # Shared data structures
        └── types.go           # Common types and connection event definitions
```

### File Descriptions

#### eBPF Programs (Kernel Space)
- **`bpf/tracer.bpf.c`**: Core eBPF program that hooks into kernel network functions to capture TCP/UDP connection events. Defines connection event structure and ring buffer for efficient data transfer to user space.

#### Go Packages (User Space)
- **`cmd/procnet/main.go`**: Main application entry point with command-line flag parsing, signal handling, and coordination of eBPF tracer and output formatting.

- **`pkg/ebpf/ebpf.go`**: eBPF program lifecycle management including loading, attaching to kernel hooks, processing ring buffer events, and cleanup. Contains the core tracer logic.

- **`pkg/cache/cache.go`**: LRU cache implementation for process information lookup, reducing /proc filesystem access overhead for repeated PID queries.

- **`pkg/filter/whitelist.go`**: SHA256-based process filtering system for suppressing output from trusted processes, with file-based persistence and interactive TUI management.

- **`pkg/logger/rotating.go`**: Rotating JSON Lines logger with configurable file size limits and rotation policies, providing persistent structured logging for connection events.

- **`pkg/output/output.go`**: Event formatting and output handling, supporting human-readable text, JSON, and rotating JSONL output formats for connection events.

- **`pkg/theme/theme.go`**: TUI theme system providing multiple color schemes (dark, light, monochrome, blue, rainbow) with consistent styling across all interface elements including tables, popups, and help text.

- **`pkg/tui/model.go`**: Terminal User Interface implementation using Bubble Tea framework, providing interactive real-time connection monitoring with sortable columns, connection grouping, cache management, detailed popup views, and theme support.

- **`pkg/types/types.go`**: Shared data structures and type definitions used across packages, including connection event types and configuration options.

#### Build System
- **`Makefile`**: Comprehensive build automation supporting eBPF compilation, Go builds, code generation, testing, and development workflow commands.


