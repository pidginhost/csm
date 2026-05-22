//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// recordReadTruncation increments csm_realtime_content_scan_truncated_total
// when the file behind fd is larger than the requested read window. Pins
// the wiring and the boundary: a file at exactly the cap must not
// increment; a file one byte over must.
func TestRecordReadTruncationIncrementsCounterWhenFileExceedsCap(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	fm := &FileMonitor{
		cfg:        &config.Config{},
		alertCh:    ch,
		analyzerCh: make(chan fileEvent, 4000),
	}
	fm.registerMetrics()

	dir := t.TempDir()
	exactly := filepath.Join(dir, "exactly.php")
	over := filepath.Join(dir, "over.php")
	if err := os.WriteFile(exactly, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(over, make([]byte, 8192), 0o644); err != nil {
		t.Fatal(err)
	}

	exactlyFD, err := os.Open(exactly)
	if err != nil {
		t.Fatal(err)
	}
	defer exactlyFD.Close()
	overFD, err := os.Open(over)
	if err != nil {
		t.Fatal(err)
	}
	defer overFD.Close()

	before := readLabelledCounter(scrapeBody(t),
		"csm_realtime_content_scan_truncated_total", "check", "unit_test")

	// File size 4096 == cap 4096: not truncated, counter must NOT advance.
	recordReadTruncation(int(exactlyFD.Fd()), 4096, "unit_test")
	mid := readLabelledCounter(scrapeBody(t),
		"csm_realtime_content_scan_truncated_total", "check", "unit_test")
	if mid != before {
		t.Errorf("file at cap must not count as truncation: before=%g after=%g", before, mid)
	}

	// File size 8192 > cap 4096: truncated, counter increments.
	recordReadTruncation(int(overFD.Fd()), 4096, "unit_test")
	after := readLabelledCounter(scrapeBody(t),
		"csm_realtime_content_scan_truncated_total", "check", "unit_test")
	if after-mid != 1 {
		t.Errorf("file over cap must increment counter by 1: before=%g after=%g", mid, after)
	}
}

// readLabelledCounter returns the value of a single sample of a labelled
// counter, 0 if not present. Matches the line shape OpenMetrics emits:
//
//	csm_realtime_content_scan_truncated_total{check="unit_test"} 1
func readLabelledCounter(body, name, label, value string) float64 {
	prefix := name + "{" + label + "=\"" + value + "\"} "
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		parts := strings.Fields(trimmed)
		if len(parts) < 2 {
			continue
		}
		if f, err := strconv.ParseFloat(parts[1], 64); err == nil {
			return f
		}
	}
	return 0
}
