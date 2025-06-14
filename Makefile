# Go eBPF Tracer Makefile
GO ?= go
BPFTOOL ?= bpftool

TARGET = egress-tracer
VMLINUX = include/vmlinux.h
PKG_DIRS = pkg/types pkg/cache pkg/output pkg/ebpf pkg/tui

.PHONY: all clean vmlinux generate build install test fmt vet tidy

all: $(TARGET)

# Generate vmlinux.h header
vmlinux: $(VMLINUX)

$(VMLINUX):
	mkdir -p include
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Generate eBPF Go bindings
generate: $(VMLINUX)
	$(GO) generate ./...

# Build the main Go binary (cmd/procnet)
build: generate
	$(GO) build -o $(TARGET) ./cmd/procnet

$(TARGET): build

# Test all packages
test: generate
	$(GO) test ./...

# Run tests with coverage
test-coverage: generate
	$(GO) test -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# Format all Go code
fmt:
	$(GO) fmt ./...

# Run go vet on all packages
vet: generate
	$(GO) vet ./...

# Tidy up go.mod
tidy:
	$(GO) mod tidy

# Check and fix common issues
check: fmt vet tidy test

clean:
	rm -f $(TARGET)
	rm -f pkg/ebpf/tracer_bpf*.go pkg/ebpf/tracer_bpf*.o
	rm -f coverage.out coverage.html
	rm -rf include/

install: $(TARGET)
	install -D $(TARGET) /usr/local/bin/$(TARGET)

