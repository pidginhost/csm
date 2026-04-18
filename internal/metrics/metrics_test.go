package metrics

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
)

func TestCounterAddAndInc(t *testing.T) {
	c := NewCounter("foo_total", "an example")
	c.Inc()
	c.Add(4)
	if got := c.Value(); got != 5 {
		t.Errorf("Value: got %g want 5", got)
	}
}

func TestCounterNegativePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for negative counter Add")
		}
	}()
	c := NewCounter("x", "")
	c.Add(-1)
}

func TestCounterConcurrentIncrements(t *testing.T) {
	c := NewCounter("hits", "")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c.Inc()
			}
		}()
	}
	wg.Wait()
	if got := c.Value(); got != 100000 {
		t.Errorf("concurrent inc lost writes: got %g want 100000", got)
	}
}

func TestGaugeSetAddIncDec(t *testing.T) {
	g := NewGauge("queue_depth", "")
	g.Set(5)
	g.Inc()
	g.Inc()
	g.Dec()
	g.Add(-2)
	if got := g.Value(); got != 4 {
		t.Errorf("Value: got %g want 4", got)
	}
}

func TestHistogramObserve(t *testing.T) {
	h := NewHistogram("dur_seconds", "", []float64{0.1, 1, 10})
	h.Observe(0.05)
	h.Observe(0.5)
	h.Observe(5)
	h.Observe(50)
	h.Observe(100)

	var buf bytes.Buffer
	bw := newBufferedWriter(&buf)
	h.writeTo(bw)
	out := buf.String()

	// le="0.1" contains only the 0.05 sample
	if !strings.Contains(out, `dur_seconds_bucket{le="0.1"} 1`) {
		t.Errorf("missing le=0.1 count: %s", out)
	}
	// le="1" contains 0.05 and 0.5
	if !strings.Contains(out, `dur_seconds_bucket{le="1"} 2`) {
		t.Errorf("missing le=1 count: %s", out)
	}
	// le="10" contains 0.05, 0.5, 5
	if !strings.Contains(out, `dur_seconds_bucket{le="10"} 3`) {
		t.Errorf("missing le=10 count: %s", out)
	}
	// +Inf has all 5
	if !strings.Contains(out, `dur_seconds_bucket{le="+Inf"} 5`) {
		t.Errorf("missing +Inf count: %s", out)
	}
	// Total count and sum
	if !strings.Contains(out, `dur_seconds_count 5`) {
		t.Errorf("missing total count: %s", out)
	}
	// Sum is 0.05 + 0.5 + 5 + 50 + 100 = 155.55
	if !strings.Contains(out, `dur_seconds_sum 155.55`) {
		t.Errorf("missing sum: %s", out)
	}
}

func TestHistogramNonMonotonicBoundsPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on non-increasing buckets")
		}
	}()
	NewHistogram("x", "", []float64{1, 1, 2})
}

func TestCounterVecBranches(t *testing.T) {
	cv := NewCounterVec("findings_total", "", []string{"severity"})
	cv.With("critical").Add(3)
	cv.With("warning").Inc()
	cv.With("critical").Inc()

	if got := cv.With("critical").Value(); got != 4 {
		t.Errorf("critical: got %g want 4", got)
	}
	if got := cv.With("warning").Value(); got != 1 {
		t.Errorf("warning: got %g want 1", got)
	}
}

func TestCounterVecArityMismatchPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on wrong label value count")
		}
	}()
	cv := NewCounterVec("x", "", []string{"a", "b"})
	cv.With("only-one")
}

func TestHistogramVecScrapeShape(t *testing.T) {
	hv := NewHistogramVec("dur", "", []string{"check", "tier"}, []float64{0.1, 1, 10})
	hv.With("scan_ssh", "critical").Observe(0.05)
	hv.With("scan_ssh", "critical").Observe(0.5)
	hv.With("scan_fs", "deep").Observe(5)

	var buf bytes.Buffer
	bw := newBufferedWriter(&buf)
	hv.writeTo(bw)
	out := buf.String()

	for _, want := range []string{
		`dur_bucket{check="scan_ssh",tier="critical",le="0.1"} 1`,
		`dur_bucket{check="scan_ssh",tier="critical",le="1"} 2`,
		`dur_bucket{check="scan_ssh",tier="critical",le="+Inf"} 2`,
		`dur_sum{check="scan_ssh",tier="critical"} 0.55`,
		`dur_count{check="scan_ssh",tier="critical"} 2`,
		`dur_bucket{check="scan_fs",tier="deep",le="10"} 1`,
		`dur_count{check="scan_fs",tier="deep"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestHistogramVecNonMonotonicPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on non-monotonic buckets")
		}
	}()
	NewHistogramVec("x", "", []string{"k"}, []float64{1, 1, 2})
}

func TestGaugeVecBasics(t *testing.T) {
	gv := NewGaugeVec("queue", "", []string{"watcher"})
	gv.With("fanotify").Set(7)
	gv.With("spool").Set(3)
	if got := gv.With("fanotify").Value(); got != 7 {
		t.Errorf("fanotify: got %g want 7", got)
	}
}

func TestRegistryDuplicatePanics(t *testing.T) {
	r := NewRegistry()
	r.MustRegister("foo", NewCounter("foo", ""))
	defer func() {
		if rec := recover(); rec == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	r.MustRegister("foo", NewCounter("foo", ""))
}

func TestRegistryWriteOpenMetrics(t *testing.T) {
	r := NewRegistry()
	c := NewCounter("findings_total", "Total findings.")
	c.Add(7)
	r.MustRegister("findings_total", c)

	g := NewGauge("queue_depth", "Queue depth.")
	g.Set(12)
	r.MustRegister("queue_depth", g)

	cv := NewCounterVec("scans_total", "Scans by tier.", []string{"tier"})
	cv.With("critical").Add(3)
	cv.With("deep").Inc()
	r.MustRegister("scans_total", cv)

	r.RegisterGaugeFunc("bbolt_bytes", "bbolt file size.", func() float64 { return 1024 })
	r.RegisterCounterFunc("build_info", "Build info proxy.", func() float64 { return 1 })

	var buf bytes.Buffer
	if err := r.WriteOpenMetrics(&buf); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"# HELP findings_total Total findings.",
		"# TYPE findings_total counter",
		"findings_total 7",
		"# HELP queue_depth Queue depth.",
		"# TYPE queue_depth gauge",
		"queue_depth 12",
		"# HELP scans_total Scans by tier.",
		"# TYPE scans_total counter",
		`scans_total{tier="critical"} 3`,
		`scans_total{tier="deep"} 1`,
		"# HELP bbolt_bytes bbolt file size.",
		"# TYPE bbolt_bytes gauge",
		"bbolt_bytes 1024",
		"# HELP build_info Build info proxy.",
		"# TYPE build_info counter",
		"build_info 1",
		"# EOF",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRegistryOrderingStable(t *testing.T) {
	r := NewRegistry()
	r.MustRegister("zeta", NewCounter("zeta", ""))
	r.MustRegister("alpha", NewCounter("alpha", ""))
	r.MustRegister("mu", NewCounter("mu", ""))

	var buf bytes.Buffer
	_ = r.WriteOpenMetrics(&buf)
	out := buf.String()
	a := strings.Index(out, "# HELP alpha")
	m := strings.Index(out, "# HELP mu")
	z := strings.Index(out, "# HELP zeta")
	if a < 0 || a >= m || m >= z {
		t.Errorf("metrics not alphabetically ordered: alpha@%d mu@%d zeta@%d\n%s", a, m, z, out)
	}
}

func TestFormatFloatEdgeCases(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{-3, "-3"},
		{1.5, "1.5"},
		{math.NaN(), "NaN"},
		{math.Inf(1), "+Inf"},
		{math.Inf(-1), "-Inf"},
	}
	for _, c := range cases {
		if got := formatFloat(c.in); got != c.want {
			t.Errorf("formatFloat(%v): got %q want %q", c.in, got, c.want)
		}
	}
}

func TestEscapeLabelAndHelp(t *testing.T) {
	if got := escapeLabel(`weird "value" with \ backslash`); got != `weird \"value\" with \\ backslash` {
		t.Errorf("escapeLabel: got %q", got)
	}
	if got := escapeHelp("line one\nline two"); got != `line one\nline two` {
		t.Errorf("escapeHelp: got %q", got)
	}
}

func TestErrNotRegisteredExported(t *testing.T) {
	if !errors.Is(ErrNotRegistered, ErrNotRegistered) {
		t.Error("ErrNotRegistered sentinel should satisfy errors.Is identity")
	}
}

func TestLabelSeparatorPanicsInValue(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on label value containing unit separator")
		}
	}()
	cv := NewCounterVec("x", "", []string{"k"})
	cv.With("a\x1fb")
}
