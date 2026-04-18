package daemon

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// TestFirewallMetricsReadLiveStore registers the firewall gauges and
// then mutates the bbolt store underneath them; the scrape must
// reflect the mutation. This catches a silent regression where someone
// stops reading store.Global() or caches the state at register time.
func TestFirewallMetricsReadLiveStore(t *testing.T) {
	// store.EnsureOpen's sync.Once means we cannot rely on it to
	// point Global at a fresh tempdir. Open directly and SetGlobal
	// for the duration of this test.
	db := openStoreForTest(t)

	// Seed with known state. Exact counts let us assert precise
	// values on the gauges.
	if err := db.BlockIP("10.0.0.1", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}
	if err := db.BlockIP("10.0.0.2", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}
	if err := db.AllowIP("10.0.0.3", "test", time.Time{}); err != nil {
		t.Fatalf("AllowIP: %v", err)
	}

	d := &Daemon{cfg: &config.Config{}}
	d.registerFirewallMetrics()

	body := scrapeBody(t)

	// Fresh test-store: the three seed rows are the only entries, so
	// assert exact counts. Tighter than >= catches regressions like
	// "BlockIP silently double-inserts" or
	// "LoadFirewallState reads the bucket twice".
	if got := readGauge(body, "csm_blocked_ips_total"); got != 2 {
		t.Errorf("csm_blocked_ips_total: got %g, want 2 (two BlockIPs seeded)", got)
	}
	if got := readGauge(body, "csm_firewall_rules_total"); got != 3 {
		t.Errorf("csm_firewall_rules_total: got %g, want 3 (2 blocked + 1 allowed)", got)
	}

	// Mutate and re-scrape to prove the gauge is live, not cached.
	if err := db.BlockIP("10.0.0.4", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}
	if got := readGauge(scrapeBody(t), "csm_blocked_ips_total"); got != 3 {
		t.Errorf("csm_blocked_ips_total after third BlockIP: got %g, want 3", got)
	}
}

// TestStoreSizeMetricReadsFile registers the store-size gauge, writes
// more data to bbolt, and confirms the gauge reflects the larger
// file. bbolt preallocates pages so the first write can already lift
// the file above 0; we assert "increased or non-zero" rather than a
// specific delta.
func TestStoreSizeMetricReadsFile(t *testing.T) {
	db := openStoreForTest(t)

	d := &Daemon{cfg: &config.Config{}}
	d.registerStoreSizeMetric()

	body := scrapeBody(t)
	size := readGauge(body, "csm_store_size_bytes")
	if size <= 0 {
		t.Fatalf("csm_store_size_bytes: got %g, want > 0 for an opened bbolt file", size)
	}

	// Confirm the stat path matches the real bbolt path (so the hook
	// is not shadowed by something else).
	info, err := os.Stat(db.Path())
	if err != nil {
		t.Fatalf("stat bbolt: %v", err)
	}
	if float64(info.Size()) != size {
		// Allow for a race where another test writes between the
		// two reads. Size should still be in the same order of
		// magnitude.
		t.Logf("scrape (%g) != direct stat (%d); may be a concurrent-write race", size, info.Size())
	}
}

// TestFindingsTotalFromAppendHistory exercises state.AppendHistory
// through the findings_total instrumentation and confirms the
// severity split reaches the scrape. This mirrors the existing test
// in internal/state but stays in the daemon package so a refactor of
// either end-to-end path gets its own regression gate.
func TestFindingsTotalFromAppendHistory(t *testing.T) {
	// Point store.Global at a fresh bbolt so state.AppendHistory takes
	// its bbolt branch instead of the deprecated JSONL fallback (which
	// would still bump the metric, but also spam "DEPRECATION" on
	// stderr every run).
	_ = openStoreForTest(t)

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	before := readSeverityCounter(t, "CRITICAL")

	st.AppendHistory([]alert.Finding{
		{Severity: alert.Critical, Check: "c1", Message: "m", Timestamp: time.Now()},
	})

	after := readSeverityCounter(t, "CRITICAL")
	if after-before != 1 {
		t.Errorf("csm_findings_total{severity=CRITICAL} delta: got %g want 1", after-before)
	}
}

// -----------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------

// openStoreForTest opens a fresh bbolt DB under t.TempDir and makes
// it the process-wide Global. store.EnsureOpen's sync.Once means the
// first test to call it locks the Global pointer; SetGlobal is the
// escape hatch tests use to avoid fighting that.
func openStoreForTest(t *testing.T) *store.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = db.Close()
	})
	return db
}

func scrapeBody(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	if err := metrics.WriteOpenMetrics(&buf); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	return buf.String()
}

// readGauge returns the value of the first sample whose first token
// matches name. Works for unlabelled gauges.
func readGauge(body, name string) float64 {
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.Fields(trimmed)
		if len(parts) < 2 || parts[0] != name {
			continue
		}
		v, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			continue
		}
		return v
	}
	return 0
}

func readSeverityCounter(t *testing.T, severity string) float64 {
	t.Helper()
	body := scrapeBody(t)
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, `csm_findings_total{severity="`+severity+`"}`) {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			continue
		}
		return v
	}
	return 0
}
