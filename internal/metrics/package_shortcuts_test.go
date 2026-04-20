package metrics

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
)

// The package-level shortcuts (Default, MustRegister, RegisterCounterFunc,
// RegisterGaugeFunc, WriteOpenMetrics) delegate to defaultRegistry.
// Coverage stayed at 0% because the existing tests all construct their
// own NewRegistry() for isolation. A single test here exercises each
// shortcut through the shared registry and restores the default state
// on cleanup by picking unique metric names the rest of the suite does
// not reuse.

func TestDefaultReturnsSingleton(t *testing.T) {
	a := Default()
	b := Default()
	if a != b {
		t.Error("Default must return the same Registry across calls")
	}
	if a == nil {
		t.Fatal("Default returned nil")
	}
}

// RegisterCounterFunc (the shortcut) must wire up the func so that a
// subsequent WriteOpenMetrics includes the counter's current value.
// The callback fires on every write, so bumping `counter` between
// writes must be reflected in the output.
func TestRegisterCounterFuncShortcutWritesThroughDefaultRegistry(t *testing.T) {
	var counter int64
	name := "csm_test_shortcut_counter_total"
	RegisterCounterFunc(name, "test-only counter for shortcut coverage",
		func() float64 { return float64(atomic.LoadInt64(&counter)) })

	atomic.StoreInt64(&counter, 42)
	var buf bytes.Buffer
	if err := WriteOpenMetrics(&buf); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, name) {
		t.Errorf("expected %s in output, got:\n%s", name, out)
	}
	if !strings.Contains(out, "42") {
		t.Errorf("expected counter value 42 in output, got:\n%s", out)
	}
}

// RegisterGaugeFunc is the gauge counterpart; identical pattern.
func TestRegisterGaugeFuncShortcutWritesThroughDefaultRegistry(t *testing.T) {
	var value int64
	name := "csm_test_shortcut_gauge"
	RegisterGaugeFunc(name, "test-only gauge for shortcut coverage",
		func() float64 { return float64(atomic.LoadInt64(&value)) })

	atomic.StoreInt64(&value, 7)
	var buf bytes.Buffer
	if err := WriteOpenMetrics(&buf); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	if !strings.Contains(buf.String(), name) {
		t.Errorf("expected %s in output, got:\n%s", name, buf.String())
	}
}

// MustRegister (shortcut) registers a plain Counter on the default
// registry. After a write, the counter must appear in the output.
func TestMustRegisterShortcut(t *testing.T) {
	c := NewCounter("csm_test_shortcut_must_register_total", "shortcut coverage")
	c.Add(5)
	MustRegister("csm_test_shortcut_must_register_total", c)

	var buf bytes.Buffer
	if err := WriteOpenMetrics(&buf); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	if !strings.Contains(buf.String(), "csm_test_shortcut_must_register_total 5") {
		t.Errorf("expected shortcut counter output, got:\n%s", buf.String())
	}
}

// GaugeVec.writeTo was unreachable through the existing tests because
// none of them registered a GaugeVec on a Registry before calling
// WriteOpenMetrics. The path serialises each child into the
// Prometheus text exposition with its label pairs; verify both
// children land with their label values.
func TestGaugeVecWriteToEmitsChildren(t *testing.T) {
	r := NewRegistry()
	gv := NewGaugeVec("csm_test_queue_depth", "queue depth by watcher", []string{"watcher"})
	gv.With("fanotify").Set(3)
	gv.With("spool").Set(8)
	r.MustRegister("csm_test_queue_depth", gv)

	var buf bytes.Buffer
	if err := r.WriteOpenMetrics(&buf); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `csm_test_queue_depth{watcher="fanotify"} 3`) {
		t.Errorf("missing fanotify sample:\n%s", out)
	}
	if !strings.Contains(out, `csm_test_queue_depth{watcher="spool"} 8`) {
		t.Errorf("missing spool sample:\n%s", out)
	}
	// Output must start with # HELP / # TYPE meta lines for the metric.
	if !strings.Contains(out, "# HELP csm_test_queue_depth") {
		t.Errorf("missing HELP line:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE csm_test_queue_depth gauge") {
		t.Errorf("missing TYPE line:\n%s", out)
	}
}
