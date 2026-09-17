//go:build linux && bpf && kernelintegration

package daemon

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestKernelConnectionVerdictQueuePublishedBeforeRun(t *testing.T) {
	backend, err := startConnectionBPF(context.Background(), make(chan alert.Finding, 1), &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, closeResource := range []func() error{backend.link4.Close, backend.link6.Close, backend.reader.Close, backend.objs.Close} {
			if err := closeResource(); err != nil {
				t.Error(err)
			}
		}
	})
	d := &Daemon{}
	d.registerQueueSource("bpf.connection", backend)
	states := d.QueueStatuses()
	annotation, exists := states["bpf.connection.verdict"]
	if !exists || annotation.Capacity != 256 || annotation.Depth != 0 || annotation.InFlight != 0 || annotation.DroppedTotal != 0 || annotation.Status != "ok" {
		t.Fatalf("constructed BPF backend did not publish its annotation queue: exists=%v status=%+v", exists, annotation)
	}
	for _, name := range []string{"bpf.connection.kernel", "bpf.connection.output"} {
		state, exists := states[name]
		if !exists || state.Capacity <= 0 || state.Depth != 0 || state.DroppedTotal != 0 || state.Status != "ok" {
			t.Errorf("annotation publication damaged %s: exists=%v status=%+v", name, exists, state)
		}
	}
}
