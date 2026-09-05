//go:build linux && bpf && kernelintegration

package bpf

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestKernelReaderDeliversEvents(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := m.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	reader, err := NewReader(m, decodeTiny)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := reader.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SocketFilter, License: "GPL",
		Instructions: asm.Instructions{
			asm.StoreImm(asm.R10, -8, 42, asm.Word),
			asm.StoreImm(asm.R10, -4, 7, asm.Word),
			asm.LoadMapPtr(asm.R1, m.FD()),
			asm.Mov.Reg(asm.R2, asm.R10),
			asm.Add.Imm(asm.R2, -8),
			asm.Mov.Imm(asm.R3, 8),
			asm.Mov.Imm(asm.R4, 0),
			asm.FnRingbufOutput.Call(),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := program.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { reader.Run(ctx); close(done) }()
	for range 3 {
		result, _, err := program.Test(make([]byte, 64))
		if err != nil || result != 0 {
			t.Fatalf("kernel ring write: result=%d err=%v", result, err)
		}
	}
	for range 3 {
		select {
		case event, ok := <-reader.Events():
			if !ok || event != (tinyEvent{A: 42, B: 7}) {
				t.Fatalf("event=%+v open=%v", event, ok)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("kernel event was not delivered")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not stop")
	}
	if event, ok := <-reader.Events(); ok {
		t.Fatalf("unexpected extra event: %+v", event)
	}
	if reader.EventCount() != 3 || reader.DroppedCount() != 0 {
		t.Fatalf("delivered=%d dropped=%d", reader.EventCount(), reader.DroppedCount())
	}
}
