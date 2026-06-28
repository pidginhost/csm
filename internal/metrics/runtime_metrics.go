package metrics

import (
	"runtime"
	"sync"
)

var runtimeMetricsOnce sync.Once

// goRuntimeCollector emits Go runtime memory and scheduler stats. It reads
// runtime.ReadMemStats once per scrape (ReadMemStats briefly stops the world,
// so a single read for the whole family is deliberate -- do not split it into
// per-metric gauge hooks).
type goRuntimeCollector struct{}

func (goRuntimeCollector) writeTo(bw *bufferedWriter) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	g := func(name, help string, v float64) {
		bw.writeMeta(name, help, typeGauge)
		bw.writeSample(name, nil, v)
	}
	g("go_memstats_heap_alloc_bytes", "Heap bytes allocated and still in use.", float64(m.HeapAlloc))
	g("go_memstats_heap_inuse_bytes", "Heap bytes in in-use spans.", float64(m.HeapInuse))
	g("go_memstats_heap_idle_bytes", "Heap bytes idle, waiting to be used.", float64(m.HeapIdle))
	g("go_memstats_heap_released_bytes", "Heap bytes released to the OS.", float64(m.HeapReleased))
	g("go_memstats_heap_sys_bytes", "Heap bytes obtained from the OS.", float64(m.HeapSys))
	g("go_memstats_heap_objects", "Number of currently allocated heap objects.", float64(m.HeapObjects))
	g("go_memstats_stack_inuse_bytes", "Bytes in use by the stack allocator.", float64(m.StackInuse))
	g("go_memstats_sys_bytes", "Total bytes obtained from the OS.", float64(m.Sys))
	g("go_memstats_next_gc_bytes", "Heap size target for the next GC cycle.", float64(m.NextGC))
	g("go_memstats_gc_cpu_fraction", "Fraction of CPU time used by GC since program start.", m.GCCPUFraction)
	g("go_goroutines", "Number of goroutines that currently exist.", float64(runtime.NumGoroutine()))
}

// RegisterRuntimeMetrics adds Go runtime memory/scheduler stats to the default
// registry so they appear on the /metrics endpoint. Idempotent: safe to call on
// every daemon start (repeated starts in a test binary would otherwise panic on
// the duplicate registration).
func RegisterRuntimeMetrics() {
	runtimeMetricsOnce.Do(func() {
		defaultRegistry.MustRegister("go_runtime_stats", goRuntimeCollector{})
	})
}
