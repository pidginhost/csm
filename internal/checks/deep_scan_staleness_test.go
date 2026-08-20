package checks

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/yara"
)

// seedDeepScanCursor writes a cursor with the supplied rolling-cycle start.
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

func staleCycleWarnings(findings []alert.Finding) []alert.Finding {
	var warnings []alert.Finding
	for _, f := range findings {
		if f.Severity == alert.Warning && strings.Contains(f.Message, "has not completed a full pass") {
			warnings = append(warnings, f)
		}
	}
	return warnings
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

// Keeping every consumer active is the important ownership case: one stale
// cursor must not lend its warning to either fresh sibling.
func TestCheckYARADeepStaleWarningUsesOnlyOwningConsumerCursor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cursor string
		check  string
		label  string
	}{
		{name: "YARA", cursor: yaraDeepCursorCheck, check: "yara_scan_incomplete", label: "YARA"},
		{name: "JS", cursor: jsTaintDeepCursorCheck, check: "js_taint_scan_incomplete", label: "JS taint"},
		{name: "PHP", cursor: phpTaintDeepCursorCheck, check: "php_taint_scan_incomplete", label: "PHP taint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := useRollingStore(t)
			enablePHPTaintConsumer(t)
			root := t.TempDir()
			first := writeYARADeepFile(t, root, "a/one.php", "<?php echo 1;")
			writeYARADeepFile(t, root, "b/two.js", "var b = 2;")

			base := time.Now().UTC().Add(time.Hour)
			fresh := base.Add(-time.Hour)
			stale := base.Add(-yaraDeepFullCycleStale - 24*time.Hour)
			for _, cursor := range []string{yaraDeepCursorCheck, jsTaintDeepCursorCheck, phpTaintDeepCursorCheck} {
				wrappedAt := fresh
				if cursor == tc.cursor {
					wrappedAt = stale
				}
				seedDeepScanCursor(t, db, cursor, first, wrappedAt)
			}

			backend := &recordingYARABackend{}
			yara.SetActive(backend)
			t.Cleanup(func() { yara.SetActive(nil) })
			clock := base
			useYARADeepClock(t, &clock)
			ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin-time.Second))
			defer cancel()

			findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, nil)
			warnings := staleCycleWarnings(findings)
			wantMessage := "Rolling " + tc.label + " deep scan has not completed a full pass since " + stale.Format("2006-01-02")
			if len(warnings) != 1 || warnings[0].Check != tc.check || warnings[0].Message != wantMessage {
				t.Fatalf("stale warnings = %+v, want only %s: %s", warnings, tc.check, wantMessage)
			}
		})
	}
}

// Coverage status is per-run state even when its detection owner is partial.
// Replacing the old status must neither accumulate another warning nor purge a
// PHP/JS detection from an earlier cursor window.
func TestCheckYARADeepStaleWarningReplacesStatusAndPreservesDetection(t *testing.T) {
	for _, tc := range []struct {
		name           string
		cursor         string
		statusCheck    string
		detectionCheck string
		disabled       []string
		enable         func(*testing.T)
		label          string
	}{
		{
			name: "JS", cursor: jsTaintDeepCursorCheck,
			statusCheck: "js_taint_scan_incomplete", detectionCheck: "js_keylogger_dataflow",
			disabled: []string{"yara_deep", logicalOwnerPHPTaintDeep}, label: "JS taint",
		},
		{
			name: "PHP", cursor: phpTaintDeepCursorCheck,
			statusCheck: "php_taint_scan_incomplete", detectionCheck: "php_remote_taint",
			disabled: []string{"yara_deep", logicalOwnerJSTaintDeep}, enable: enablePHPTaintConsumer,
			label: "PHP taint",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := useRollingStore(t)
			if tc.enable != nil {
				tc.enable(t)
			}
			root := t.TempDir()
			path := writeYARADeepFile(t, root, "a/probe.php", "<?php echo 1;")
			clock := time.Now().UTC().Add(24 * time.Hour)
			wrappedAt := clock.Add(-yaraDeepFullCycleStale - 24*time.Hour)
			seedDeepScanCursor(t, db, tc.cursor, path, wrappedAt)
			useYARADeepClock(t, &clock)

			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			st.SetLatestFindings([]alert.Finding{
				{Check: tc.statusCheck, Message: "status from prior run"},
				{Check: tc.detectionCheck, Message: "detection from prior window", FilePath: path},
			})

			findings, purge := runParallelWithContext(context.Background(), &config.Config{
				AccountRoots: []string{root}, DisabledChecks: tc.disabled,
			}, st, []namedCheck{{name: "yara_deep", fn: CheckYARADeep}}, "deep", true)
			warnings := staleCycleWarnings(findings)
			wantMessage := "Rolling " + tc.label + " deep scan has not completed a full pass since " + wrappedAt.Format("2006-01-02")
			if len(warnings) != 1 || warnings[0].Check != tc.statusCheck || warnings[0].Message != wantMessage {
				t.Fatalf("stale warnings = %+v, want one current %s status", warnings, tc.statusCheck)
			}
			if !slices.Contains(purge, tc.statusCheck) || slices.Contains(purge, tc.detectionCheck) {
				t.Fatalf("purge = %v, want status replacement without detection purge", purge)
			}

			StoreLatestScanFindings(st, purge, findings)
			latestStatus := jsFindingsByCheck(st.LatestFindings(), tc.statusCheck)
			latestDetection := jsFindingsByCheck(st.LatestFindings(), tc.detectionCheck)
			if len(latestStatus) != 1 || latestStatus[0].Message != wantMessage {
				t.Fatalf("latest status = %+v, want only the current stale warning", latestStatus)
			}
			if len(latestDetection) != 1 || latestDetection[0].Message != "detection from prior window" {
				t.Fatalf("latest detection = %+v, want prior window preserved", latestDetection)
			}
		})
	}
}
