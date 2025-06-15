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
# Build main binary
make build
```

## Usage (requires root privileges)

```bash
# CLI mode
sudo ./egress-tracer

# TUI mode (Terminal User Interface)
sudo ./egress-tracer --tui

# Options for CLI mode
sudo ./egress-tracer --json                    # JSON output

# Whitelist filtering (suppress output for specific processes)
sudo ./egress-tracer --whitelist=whitelist.txt # Load SHA256 whitelist from file

# Rotating JSONL Logging
sudo ./egress-tracer --log-file=/var/log/egress-tracer.jsonl          # Enable rotating JSONL logging
sudo ./egress-tracer --log-file=/var/log/egress-tracer.jsonl \
                    --log-max-size=52428800 \                  # Max file size before rotation (50MB)
                    --log-max-files=10                         # Max number of rotated files

# Process Cache which offloads /proc lookups
sudo ./egress-tracer --cache-ttl=10m           # PID Cache TTL
sudo ./egress-tracer --cache-max-size=500      # PID Cache size

```

## Whitelist Filtering

The whitelist feature allows you to suppress output for specific processes based on their SHA256 hash.

### Whitelist File Format

Create a text file with one SHA256 hash per line:

```
# Whitelist file for egress-tracer
# Lines starting with # are comments
# Empty lines are ignored

d4f7c9e8a1b2c3d4e5f6789012345678901234567890123456789012345678901234
a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890123
```

### Getting Process SHA256 Hashes

To get the SHA256 hash of a process:

```bash
# Find process by name
ps aux | grep process_name

# Get SHA256 of the executable
sha256sum /path/to/executable

# Or use the tracer in JSON mode to see hashes
sudo ./egress-tracer --json | jq -r '.process_sha256' | sort -u
```

### Usage Examples

```bash
# CLI mode with whitelist
sudo ./egress-tracer --whitelist=trusted_processes.txt

# TUI mode with whitelist  
sudo ./egress-tracer --tui --whitelist=trusted_processes.txt

# JSON logging with whitelist
sudo ./egress-tracer --json --whitelist=trusted_processes.txt --log-file=events.jsonl
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
    ├── logger/                 # Rotating JSON Lines logging
    │   └── rotating.go        # Rotating log file implementation with size-based rotation
    ├── output/                 # Event formatting and output
    │   └── output.go          # Connection event formatting (JSON/text/JSONL)
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

- **`pkg/logger/rotating.go`**: Rotating JSON Lines logger with configurable file size limits and rotation policies, providing persistent structured logging for connection events.

- **`pkg/output/output.go`**: Event formatting and output handling, supporting human-readable text, JSON, and rotating JSONL output formats for connection events.

- **`pkg/tui/model.go`**: Terminal User Interface implementation using Bubble Tea framework, providing interactive real-time connection monitoring with sortable columns, connection grouping, cache management, and detailed popup views.

- **`pkg/types/types.go`**: Shared data structures and type definitions used across packages, including connection event types and configuration options.

#### Build System
- **`Makefile`**: Comprehensive build automation supporting eBPF compilation, Go builds, code generation, testing, and development workflow commands.


