package metrics

import (
	"bytes"
	"strings"
	"testing"
)

func TestRuntimeCollectorEmitsMemStats(t *testing.T) {
	r := NewRegistry()
	r.MustRegister("go_runtime_stats", goRuntimeCollector{})

	var buf bytes.Buffer
	if err := r.WriteOpenMetrics(&buf); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"go_memstats_heap_alloc_bytes",
		"go_memstats_heap_inuse_bytes",
		"go_memstats_heap_idle_bytes",
		"go_memstats_heap_released_bytes",
		"go_memstats_heap_sys_bytes",
		"go_memstats_next_gc_bytes",
		"go_memstats_gc_cpu_fraction",
		"go_goroutines",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
	// heap_alloc is always > 0 in a running program; assert a real sample line,
	// not just the HELP/TYPE metadata.
	if !strings.Contains(out, "\ngo_memstats_heap_alloc_bytes ") && !strings.HasPrefix(out, "go_memstats_heap_alloc_bytes ") {
		t.Errorf("no go_memstats_heap_alloc_bytes sample line in:\n%s", out)
	}
}

func TestRegisterRuntimeMetricsIsIdempotent(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("RegisterRuntimeMetrics panicked on repeated calls: %v", rec)
		}
	}()

	RegisterRuntimeMetrics()
	RegisterRuntimeMetrics()

	var buf bytes.Buffer
	if err := WriteOpenMetrics(&buf); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	out := buf.String()
	if count := strings.Count(out, "# HELP go_memstats_heap_alloc_bytes "); count != 1 {
		t.Fatalf("go runtime metrics registered %d times, want 1:\n%s", count, out)
	}
}
