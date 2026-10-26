package daemon

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/workerproc"
)

// freshParseWorkerMetrics swaps in unregistered metrics and returns a
// registry holding only them.
func freshParseWorkerMetrics(t *testing.T) *metrics.Registry {
	t.Helper()
	jobs, starts, memory := parseJobsTotal, parseStartsTotal, parseMemoryBytes
	t.Cleanup(func() { parseJobsTotal, parseStartsTotal, parseMemoryBytes = jobs, starts, memory })
	parseJobsTotal, parseStartsTotal, parseMemoryBytes = newParseWorkerMetrics()
	r := metrics.NewRegistry()
	r.MustRegister("csm_parse_worker_jobs_total", parseJobsTotal)
	r.MustRegister("csm_parse_worker_starts_total", parseStartsTotal)
	r.MustRegister("csm_parse_worker_memory_bytes", parseMemoryBytes)
	return r
}

func TestParseWorkerMetricsRecordJobs(t *testing.T) {
	r := freshParseWorkerMetrics(t)
	recordParseJob("mail", workerproc.OutcomeOK, 64<<20)
	recordParseJob("zip", workerproc.ReasonCrash, 0)

	launch := countParseWorkerStarts("mail", func(context.Context) (workerproc.Process, error) {
		return nil, nil
	})
	if _, err := launch(context.Background()); err != nil {
		t.Fatal(err)
	}
	failing := countParseWorkerStarts("mail", func(context.Context) (workerproc.Process, error) {
		return nil, errors.New("no unit")
	})
	_, _ = failing(context.Background())

	var buf bytes.Buffer
	if err := r.WriteOpenMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		`csm_parse_worker_jobs_total{pool="mail",outcome="ok"} 1`,
		`csm_parse_worker_jobs_total{pool="zip",outcome="crash"} 1`,
		`csm_parse_worker_starts_total{pool="mail"} 1`,
		`csm_parse_worker_memory_bytes_count{pool="mail"} 1`,
		`csm_parse_worker_memory_bytes_bucket{pool="mail",le="33554432"} 0`,
		`csm_parse_worker_memory_bytes_bucket{pool="mail",le="67108864"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output lacks %s\n%s", want, out)
		}
	}
	if strings.Contains(out, `csm_parse_worker_memory_bytes_count{pool="zip"}`) {
		t.Error("a failed job recorded a memory sample")
	}
}
