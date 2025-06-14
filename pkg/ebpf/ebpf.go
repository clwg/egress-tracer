package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/clwg/egress-tracer/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tracer ../../bpf/tracer.bpf.c -- -I../../include

// Tracer manages eBPF program lifecycle and event processing
type Tracer struct {
	objs        tracerObjects
	connectLink link.Link
	sendtoLink  link.Link
	reader      *ringbuf.Reader
}

// New creates a new eBPF tracker instance
func New() (*Tracer, error) {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	// Load pre-compiled programs and maps into the kernel
	spec, err := loadTracer()
	if err != nil {
		return nil, err
	}

	var objs tracerObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, err
	}

	tracer := &Tracer{
		objs: objs,
	}

	// Attach tracepoints
	if err := tracer.attachTracepoints(); err != nil {
		tracer.Close()
		return nil, err
	}

	// Open ringbuf reader
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tracer.Close()
		return nil, err
	}
	tracer.reader = reader

	return tracer, nil
}

// attachTracepoints attaches the eBPF programs to kernel tracepoints
func (t *Tracer) attachTracepoints() error {
	var err error

	t.connectLink, err = link.Tracepoint("syscalls", "sys_enter_connect", t.objs.TraceSysEnterConnect, nil)
	if err != nil {
		return err
	}

	t.sendtoLink, err = link.Tracepoint("syscalls", "sys_enter_sendto", t.objs.TraceSysEnterSendto, nil)
	if err != nil {
		return err
	}

	return nil
}

// ReadEvent reads the next event from the ringbuffer
func (t *Tracer) ReadEvent() (*types.ConnectionEvent, error) {
	record, err := t.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		log.Printf("Reading from reader: %v", err)
		return nil, err
	}

	var event types.ConnectionEvent
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		log.Printf("Parsing ringbuf event: %v", err)
		return nil, err
	}

	return &event, nil
}

// Close cleans up all eBPF resources
func (t *Tracer) Close() error {
	var errs []error

	if t.reader != nil {
		if err := t.reader.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if t.connectLink != nil {
		if err := t.connectLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if t.sendtoLink != nil {
		if err := t.sendtoLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	t.objs.Close()

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}
