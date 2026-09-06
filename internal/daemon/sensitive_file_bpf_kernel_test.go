//go:build linux && bpf && kernelintegration

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/pidginhost/csm/internal/bpf"
	bpfprog "github.com/pidginhost/csm/internal/daemon/sensitive_file_bpfprog"
)

type countedBPFClose struct{ count int }

func (c *countedBPFClose) Close() error { c.count++; return nil }

func TestKernelSensitiveFileStartupClosesReaderOnWatchsetFailure(t *testing.T) {
	events, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = events.Close() }()
	watched, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 16, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	// A closed watch map forces population to fail after the reader owns its FDs.
	if err = watched.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := bpf.NewReader(events, decodeSensitiveFileEvent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	attachment := &countedBPFClose{}
	s := &sensitiveFileBPF{objs: &bpfprog.SensitiveFileObjects{SensitiveFileMaps: bpfprog.SensitiveFileMaps{Events: events, Watched: watched}}, reader: reader, link: attachment}
	if err := s.initializeWatchset(); err == nil {
		t.Fatal("watchset population succeeded with a closed map")
	}
	if attachment.count != 1 || events.FD() != -1 {
		t.Fatalf("cleanup: link closes=%d event fd=%d", attachment.count, events.FD())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { reader.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("startup failure left the ring reader open")
	}
}
