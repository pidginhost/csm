package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/yara"
)

// seedDeepScanCursor writes a cursor whose rolling cycle began long enough ago
// to be stale.
func seedDeepScanCursor(t *testing.T, db *store.DB, check, lastPath string, wrappedAt time.Time) {
	t.Helper()
	var record store.ScanCursorRecord
	record.Check = check
	record.LastPath = lastPath
	record.WrappedAt = wrappedAt
	if err := db.PutScanCursor(record); err != nil {
		t.Fatal(err)
	}
}

func hasStaleCycleWarning(findings []alert.Finding, check string) bool {
	for _, f := range findings {
		if f.Check == check && f.Severity == alert.Warning && strings.Contains(f.Message, "full pass") {
			return true
		}
	}
	return false
}

// A PHP rolling cycle that never completes must report its own staleness. The
// warning used to be keyed on the YARA consumer's cursor, so a stalled PHP
// cycle was silent -- and with yara_deep disabled, which is supported, nothing
// warned at all.
func TestCheckYARADeepWarnsWhenPHPFullCycleStale(t *testing.T) {
	db := useRollingStore(t)
	enablePHPTaintConsumer(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a/one.php", "<?php $x = curl_exec($c);")
	writeYARADeepFile(t, root, "b/two.php", "<?php $y = curl_exec($c);")
	withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
		return phptaint.Report{Status: phptaint.StatusAnalyzed}
	})
	seedDeepScanCursor(t, db, phpTaintDeepCursorCheck, first,
		time.Now().UTC().Add(-yaraDeepFullCycleStale-24*time.Hour))

	base := time.Now().Add(time.Hour)
	clock := base
	useYARADeepClock(t, &clock)

	// Soft deadline already passed at entry, so the run stops early with the
	// cycle still incomplete.
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin-time.Second))
	defer cancel()

	findings := CheckYARADeep(ctx, &config.Config{
		AccountRoots:   []string{root},
		DisabledChecks: []string{"yara_deep", logicalOwnerJSTaintDeep},
	}, nil)

	if !hasStaleCycleWarning(findings, "php_taint_scan_incomplete") {
		t.Fatalf("stale PHP rolling cycle produced no full-pass warning: %+v", findings)
	}
}

// Same for the JS consumer.
func TestCheckYARADeepWarnsWhenJSFullCycleStale(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a/one.js", "var a = 1;")
	writeYARADeepFile(t, root, "b/two.js", "var b = 2;")
	seedDeepScanCursor(t, db, jsTaintDeepCursorCheck, first,
		time.Now().UTC().Add(-yaraDeepFullCycleStale-24*time.Hour))

	base := time.Now().Add(time.Hour)
	clock := base
	useYARADeepClock(t, &clock)

	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin-time.Second))
	defer cancel()

	findings := CheckYARADeep(ctx, &config.Config{
		AccountRoots:   []string{root},
		DisabledChecks: []string{"yara_deep", logicalOwnerPHPTaintDeep},
	}, nil)

	if !hasStaleCycleWarning(findings, "js_taint_scan_incomplete") {
		t.Fatalf("stale JS rolling cycle produced no full-pass warning: %+v", findings)
	}
}

// The YARA warning must survive the refactor that generalised it.
func TestCheckYARADeepStillWarnsWhenYARAFullCycleStale(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a/one.dat", "mal one")
	writeYARADeepFile(t, root, "b/two.dat", "mal two")
	seedDeepScanCursor(t, db, yaraDeepCursorCheck, first,
		time.Now().UTC().Add(-yaraDeepFullCycleStale-24*time.Hour))

	base := time.Now().Add(time.Hour)
	clock := base
	backend := &recordingYARABackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	useYARADeepClock(t, &clock)

	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin-time.Second))
	defer cancel()

	findings := CheckYARADeep(ctx, &config.Config{
		AccountRoots:   []string{root},
		DisabledChecks: []string{logicalOwnerJSTaintDeep, logicalOwnerPHPTaintDeep},
	}, nil)

	if !hasStaleCycleWarning(findings, "yara_scan_incomplete") {
		t.Fatalf("stale YARA rolling cycle produced no full-pass warning: %+v", findings)
	}
}
