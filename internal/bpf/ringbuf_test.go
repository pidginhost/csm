//go:build linux && bpf

package bpf

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

type tinyEvent struct {
	A uint32
	B uint32
}

func decodeTiny(b []byte) (tinyEvent, error) {
	if len(b) < 8 {
		return tinyEvent{}, errors.New("short")
	}
	return tinyEvent{
		A: binary.LittleEndian.Uint32(b[0:4]),
		B: binary.LittleEndian.Uint32(b[4:8]),
	}, nil
}

func TestReaderDeliversEvents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs CAP_BPF")
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 4096})
	if err != nil {
		t.Fatalf("NewMap ringbuf: %v", err)
	}
	defer m.Close()

	// Userspace cannot push directly into a ringbuf (kernel side does
	// bpf_ringbuf_output). For the unit test we exercise Reader's
	// channel and shutdown semantics with a Map already created;
	// integration coverage of the kernel-side write happens in each
	// feature plan's BPF program tests.
	r, err := NewReader(m, decodeTiny)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go r.Run(ctx)

	select {
	case _, ok := <-r.Events():
		if ok {
			t.Fatal("got an event without anyone writing one")
		}
		// Closed after ctx cancellation: expected.
	case <-ctx.Done():
		<-r.Events() // wait for Run to close the channel
	}
}
