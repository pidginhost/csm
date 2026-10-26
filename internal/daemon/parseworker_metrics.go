package daemon

import (
	"context"
	"sync"

	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/workerproc"
)

// Parse worker metrics, per pool ("mail" or "zip"). Nil until
// registerParseWorkerMetrics runs; callers nil-check.
var (
	parseWorkerMetricsOnce sync.Once
	parseJobsTotal         *metrics.CounterVec
	parseStartsTotal       *metrics.CounterVec
	parseMemoryBytes       *metrics.HistogramVec
)

func newParseWorkerMetrics() (jobs, starts *metrics.CounterVec, memory *metrics.HistogramVec) {
	jobs = metrics.NewCounterVec("csm_parse_worker_jobs_total",
		"Parse worker jobs by pool and outcome: ok, timeout, oom, crash, protocol (reply rejected), spawn (unit did not start), refused (failing repeatedly) or skipped (the message killed workers before).",
		[]string{"pool", "outcome"})
	starts = metrics.NewCounterVec("csm_parse_worker_starts_total",
		"Parse worker units started, by pool.",
		[]string{"pool"})
	memory = metrics.NewHistogramVec("csm_parse_worker_memory_bytes",
		"Parse worker memory and swap in use after a successful job, by pool.",
		[]string{"pool"},
		[]float64{32 << 20, 64 << 20, 128 << 20, 256 << 20, 384 << 20, 512 << 20, 768 << 20, 1024 << 20})
	// Both labels come from fixed sets.
	jobs.SetMaxChildren(32)
	starts.SetMaxChildren(4)
	memory.SetMaxChildren(4)
	return jobs, starts, memory
}

func registerParseWorkerMetrics() {
	parseWorkerMetricsOnce.Do(func() {
		parseJobsTotal, parseStartsTotal, parseMemoryBytes = newParseWorkerMetrics()
		metrics.MustRegister("csm_parse_worker_jobs_total", parseJobsTotal)
		metrics.MustRegister("csm_parse_worker_starts_total", parseStartsTotal)
		metrics.MustRegister("csm_parse_worker_memory_bytes", parseMemoryBytes)
	})
}

// recordParseJob counts one job of pool and, for a successful one with a
// known memory use, records that use.
func recordParseJob(pool, outcome string, memory uint64) {
	if parseJobsTotal != nil {
		parseJobsTotal.With(pool, outcome).Inc()
	}
	if outcome == workerproc.OutcomeOK && memory > 0 && parseMemoryBytes != nil {
		parseMemoryBytes.With(pool).Observe(float64(memory))
	}
}

// countParseWorkerStarts counts each unit of pool that launch starts.
func countParseWorkerStarts(pool string, launch workerproc.Launcher) workerproc.Launcher {
	return func(ctx context.Context) (workerproc.Process, error) {
		proc, err := launch(ctx)
		if err == nil && parseStartsTotal != nil {
			parseStartsTotal.With(pool).Inc()
		}
		return proc, err
	}
}
