package checks

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/state"
)

// Scan-health findings describe a degraded condition, not an event. A count
// or stack trace that differs between scan cycles must not mint a new alert
// identity, or every cycle emails the operator again instead of following the
// normal reminder window.
func assertSameHealthIdentity(t *testing.T, first, second alert.Finding) {
	t.Helper()
	if first.Message == second.Message && first.Details == second.Details {
		t.Fatalf("fixture does not vary between scans: %+v", first)
	}
	if first.Key() != second.Key() {
		t.Fatalf("identity changed between scans:\n first=%q\nsecond=%q", first.Key(), second.Key())
	}
	if first.Fingerprint() != second.Fingerprint() {
		t.Fatalf("fingerprint changed between scans: %q vs %q", first.Fingerprint(), second.Fingerprint())
	}
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	st.Update([]alert.Finding{first})
	if fresh := st.FilterNew([]alert.Finding{second}); len(fresh) != 0 {
		t.Fatalf("second scan of an unchanged condition alerted again: %+v", fresh)
	}
}

func assertDistinctHealthIdentity(t *testing.T, a, b alert.Finding) {
	t.Helper()
	if a.Key() == b.Key() {
		t.Fatalf("distinct conditions share identity %q:\n a=%+v\n b=%+v", a.Key(), a, b)
	}
}

func phpTaintGapFindingsFor(routine, defeats int) []alert.Finding {
	g := newPHPTaintGapCollector()
	for i := 0; i < routine; i++ {
		g.record(fmt.Sprintf("/home/exampleuser/public_html/routine-%d.php", i), phptaint.StatusParseError.String())
	}
	for i := 0; i < defeats; i++ {
		g.record(fmt.Sprintf("/home/exampleuser/public_html/defeat-%d.php", i), phptaint.StatusPanic.String())
	}
	return g.findings()
}

func TestPHPTaintScanIncompleteIdentityIgnoresCounts(t *testing.T) {
	first := phpTaintGapFindingsFor(74, 3)
	second := phpTaintGapFindingsFor(6, 1)
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("want routine and analyzer-defeat findings, got %d and %d", len(first), len(second))
	}
	assertSameHealthIdentity(t, first[0], second[0])
	assertDistinctHealthIdentity(t, first[1], second[1])
	assertDistinctHealthIdentity(t, first[0], first[1])

	// A cycle that loses only unreadable ranges reports the same degraded
	// coverage condition as one that loses known files.
	unknownOnly := newPHPTaintGapCollector()
	unknownOnly.recordUnknownRange("/home/exampleuser/public_html")
	assertSameHealthIdentity(t, first[0], unknownOnly.findings()[0])
}

func TestPHPTaintAnalyzerDefeatIdentityTracksEveryPath(t *testing.T) {
	build := func(paths ...string) alert.Finding {
		g := newPHPTaintGapCollector()
		for _, path := range paths {
			g.record(path, phptaint.StatusPanic.String())
		}
		return g.findings()[0]
	}
	prefix := "/home/exampleuser/public_html/" + strings.Repeat("a", phpTaintExampleMaxBytes)
	first := build(prefix+"first.php", prefix+"second.php")
	reordered := build(prefix+"second.php", prefix+"first.php")
	if first.Key() != reordered.Key() || first.Fingerprint() != reordered.Fingerprint() {
		t.Fatal("scan order changed the identity of the same analyzer failures")
	}
	changed := build(prefix+"first.php", prefix+"third.php")
	if first.Details != changed.Details {
		t.Fatal("fixture must hide the changed path outside the display example")
	}
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	st.Update([]alert.Finding{first})
	st.DismissFinding(first.Key())
	if fresh := st.FilterNew([]alert.Finding{reordered, changed}); len(fresh) != 1 || fresh[0].Key() != changed.Key() {
		t.Fatalf("dismissal must cover only the same failing files, got %+v", fresh)
	}
}

func TestPHPTaintAnalyzerDefeatIdentityIncludesSnapshot(t *testing.T) {
	withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
		return phptaint.Report{Status: phptaint.StatusPanic}
	})
	build := func(content string) alert.Finding {
		g := newPHPTaintGapCollector()
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
		analyzePHPTaintSnapshot(context.Background(), "/home/exampleuser/public_html/app.php", digest, []byte(content), g)
		return g.findings()[0]
	}
	first := build("<?php /* first input */")
	if first.Key() != build("<?php /* first input */").Key() {
		t.Fatal("identical analyzer input changed identity")
	}
	assertDistinctHealthIdentity(t, first, build("<?php /* different input */"))
}

func TestPHPTaintAnalyzerDefeatIdentitySurvivesPathRetentionLimits(t *testing.T) {
	for _, unstable := range []bool{false, true} {
		t.Run(fmt.Sprint(unstable), func(t *testing.T) {
			build := func(path string) alert.Finding {
				g := newPHPTaintGapCollector()
				if unstable {
					g.resolveAliases = func(string) ([]string, bool) { return nil, false }
				} else {
					for i := 0; i < maxPHPTaintGapPaths; i++ {
						g.paths[fmt.Sprint(i)] = struct{}{}
					}
				}
				g.record(path, phptaint.StatusTimeout.String())
				if !g.pathsIncomplete() {
					t.Fatal("fixture did not exhaust path retention")
				}
				found := g.findings()
				return found[len(found)-1]
			}
			assertDistinctHealthIdentity(t, build("/home/exampleuser/public_html/first.php"), build("/home/exampleuser/public_html/second.php"))
		})
	}
}

func TestPHPTaintAnalyzerDefeatIdentityIncludesOverflow(t *testing.T) {
	build := func(last string) alert.Finding {
		g := newPHPTaintGapCollector()
		for i := 0; i < maxPHPTaintGapPaths; i++ {
			g.record(fmt.Sprintf("/home/exampleuser/public_html/file-%d.php", i), phptaint.StatusPanic.String())
		}
		g.record(last, phptaint.StatusPanic.String())
		if len(g.defeatInputs) != maxPHPTaintGapPaths || g.defeatOverflow == nil {
			t.Fatal("defeat evidence was not bounded with overflow preserved")
		}
		return g.findings()[0]
	}
	first := build("/home/exampleuser/public_html/first.php")
	second := build("/home/exampleuser/public_html/second.php")
	if first.Details != second.Details {
		t.Fatal("overflow fixture changed displayed details")
	}
	assertDistinctHealthIdentity(t, first, second)
}

func TestScanHealthDismissalRearmsAfterRecovery(t *testing.T) {
	for _, check := range []string{"php_taint_scan_incomplete", "js_taint_scan_incomplete", "yara_scan_incomplete", "db_content_scan_incomplete", "email_password_audit_incomplete"} {
		t.Run(check, func(t *testing.T) {
			dir := t.TempDir()
			st, err := state.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			identity := "coverage_gap"
			if check == "db_content_scan_incomplete" {
				identity = dbContentHostCoverageDedupKey
			}
			f := alert.Finding{Check: check, DedupKey: identity, Message: "Incomplete scan", Severity: alert.Warning}
			st.Update([]alert.Finding{f})
			StoreLatestScanFindings(st, []string{check}, []alert.Finding{f})
			st.DismissFinding(f.Key())
			st.DismissLatestFinding(f.Key())
			// Other tiers and a skipped owner do not prove recovery. Updating
			// the dispatch batch alone must not clear the dismissal either.
			st.Update(nil)
			StoreLatestScanFindings(st, []string{"unrelated_check"}, nil)
			StoreLatestScanFindings(st, nil, nil)
			StoreLatestScanFindings(st, []string{check}, []alert.Finding{f})
			if fresh := st.FilterNew([]alert.Finding{f}); len(fresh) != 0 {
				t.Fatalf("ongoing condition re-armed: %+v", fresh)
			}
			st.DismissLatestFinding(f.Key())
			StoreLatestScanFindings(st, []string{check}, nil)
			// Reopen before Close so a missing recovery save cannot be hidden
			// by the normal shutdown flush.
			reopened, err := state.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			st = reopened
			t.Cleanup(func() { _ = st.Close() })
			if fresh := st.FilterNew([]alert.Finding{f}); len(fresh) != 1 {
				t.Fatalf("resolved coverage gap stayed dismissed after restart: %+v", fresh)
			}
		})
	}
}

func TestDatabaseHealthRecoveryPreservesUnexaminedInstallDismissal(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	limit := alert.Finding{Check: "db_content_scan_incomplete", DedupKey: "example-install", Message: "Multisite limit"}
	st.SetBaseline([]alert.Finding{limit})
	StoreLatestScanFindings(st, []string{limit.Check}, []alert.Finding{{
		Check: limit.Check, DedupKey: dbContentHostCoverageDedupKey, Message: "Install unreachable",
	}})
	if fresh := st.FilterNew([]alert.Finding{limit}); len(fresh) != 0 {
		t.Fatal("missing install result cleared its existing limit acknowledgment")
	}
}

func TestAccountScanPanicIdentityIncludesAccount(t *testing.T) {
	check := namedCheck{"example_check", func(context.Context, *config.Config, *state.Store) []alert.Finding {
		panic("crafted input")
	}}
	run := func(account string) alert.Finding {
		ctx := ContextWithAccountScope(context.Background(), account)
		return runAccountScanCheck(ctx, check, &config.Config{}, nil, time.Second)[0]
	}
	first, second := run("exampleuser"), run("otheruser")
	assertDistinctHealthIdentity(t, first, second)
	if first.TenantID != "exampleuser" || second.TenantID != "otheruser" {
		t.Fatalf("panic findings lost account attribution: %+v, %+v", first, second)
	}
}

func TestCheckPanicDismissalRearmsOnlyAfterItsCheckReturns(t *testing.T) {
	for _, account := range []string{"", "exampleuser"} {
		t.Run("scope="+account, func(t *testing.T) {
			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			ctx := ContextWithAccountScope(context.Background(), account)
			run := func(ctx context.Context, name string, fn func(context.Context, *config.Config, *state.Store) []alert.Finding) []alert.Finding {
				check := namedCheck{name, fn}
				if account != "" {
					return runAccountScanCheck(ctx, check, &config.Config{}, st, time.Second)
				}
				found, _ := runParallelWithContext(ctx, &config.Config{}, st, []namedCheck{check}, "test", true)
				return found
			}
			panics := func(context.Context, *config.Config, *state.Store) []alert.Finding { panic("crafted input") }
			clean := func(context.Context, *config.Config, *state.Store) []alert.Finding { return nil }
			first := run(ctx, "example_check", panics)
			if len(first) != 1 || first[0].Check != "check_panic" {
				t.Fatalf("panic not reported: %+v", first)
			}
			st.Update(first)
			st.DismissFinding(first[0].Key())
			run(ctx, "other_check", clean)
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			run(cancelled, "example_check", clean)
			if fresh := st.FilterNew(run(ctx, "example_check", panics)); len(fresh) != 0 {
				t.Fatal("unrelated or cancelled check re-armed a dismissal")
			}
			run(ctx, "example_check", clean)
			if fresh := st.FilterNew(run(ctx, "example_check", panics)); len(fresh) != 1 {
				t.Fatal("a recovered check's next panic stayed dismissed")
			}
		})
	}
}

func TestJSTaintScanIncompleteIdentityIgnoresCounts(t *testing.T) {
	build := func(n int) alert.Finding {
		g := newJSTaintGapCollector()
		for i := 0; i < n; i++ {
			g.record(fmt.Sprintf("/home/exampleuser/public_html/app-%d.js", i), "parse_error")
		}
		return g.finding()
	}
	assertSameHealthIdentity(t, build(314), build(124))
}

func TestYARAScanIncompleteIdentityIgnoresCounts(t *testing.T) {
	build := func(n int) alert.Finding {
		g := newYARAGapCollector()
		for i := 0; i < n; i++ {
			g.record(fmt.Sprintf("/home/exampleuser/public_html/file-%d.php", i), "read_error")
		}
		return g.finding()
	}
	assertSameHealthIdentity(t, build(12), build(3))
}

func TestDatabaseScanIncompleteIdentityIgnoresCoverageDetails(t *testing.T) {
	build := func(skipped int) alert.Finding {
		ctx, _ := withIncompleteCheckCollector(context.Background())
		markCheckIncomplete(ctx, "db_content")
		coverage := &dbScanCoverage{discovered: 40}
		for i := 0; i < skipped; i++ {
			coverage.record("query_failed", fmt.Sprintf("/home/exampleuser%d/public_html/wp-config.php", i))
		}
		findings := appendDatabaseScanIncompleteFinding(ctx, nil, coverage)
		if len(findings) != 1 || findings[0].Check != "db_content_scan_incomplete" {
			t.Fatalf("findings = %+v, want one db_content_scan_incomplete", findings)
		}
		return findings[0]
	}
	assertSameHealthIdentity(t, build(4), build(1))
}

func TestAccountScanTruncatedIdentityIgnoresDroppedCount(t *testing.T) {
	build := func(account string, dropped, cap int) alert.Finding {
		ctx, collector := withAccountScanTruncationCollector(context.Background())
		recordAccountScanTruncated(ContextWithAccountScope(ctx, account), dropped, cap)
		findings := collector.findings(time.Now())
		if len(findings) != 1 {
			t.Fatalf("findings = %+v, want one", findings)
		}
		return findings[0]
	}
	assertSameHealthIdentity(t, build("exampleuser", 120, 50), build("exampleuser", 80, 50))
	assertDistinctHealthIdentity(t, build("exampleuser", 120, 50), build("otheruser", 120, 50))
	assertDistinctHealthIdentity(t, build("exampleuser", 120, 50), build("exampleuser", 120, 100))
	assertDistinctHealthIdentity(t, build("", 120, 50), build("exampleuser", 120, 50))
}

func TestCheckPanicIdentityIgnoresStackTrace(t *testing.T) {
	previous := timeoutForFunc
	t.Cleanup(func() { timeoutForFunc = previous })
	timeoutForFunc = func(string) time.Duration { return 5 * time.Second }
	run := func(name string) alert.Finding {
		findings, _ := runParallel(&config.Config{}, nil, []namedCheck{{
			name: name,
			fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
				panic("crafted input")
			},
		}}, "test", true)
		if len(findings) != 1 || findings[0].Check != "check_panic" {
			t.Fatalf("findings = %+v, want one check_panic", findings)
		}
		return findings[0]
	}
	first := run("panic_check")
	second := run("panic_check")
	assertSameHealthIdentity(t, first, second)
	assertDistinctHealthIdentity(t, first, run("other_panic_check"))
}

func TestEmailPasswordAuditIncompleteIdentityIgnoresMailboxCount(t *testing.T) {
	withTestStore(t)
	withWeakPasswords(t, []string{"fixture-secret-123"})
	withTestHIBP(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	path := t.TempDir() + "/shadow"
	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{"/home/exampleuser/etc/example.test/shadow"}, nil },
		open: func(string) (*os.File, error) { return os.Open(path) },
	})
	run := func(unsupported int) alert.Finding {
		var shadow strings.Builder
		for i := 0; i < unsupported; i++ {
			fmt.Fprintf(&shadow, "mailbox%d:{UNKNOWN}private-fixture\n", i)
		}
		if err := os.WriteFile(path, []byte(shadow.String()), 0600); err != nil {
			t.Fatal(err)
		}
		for _, f := range CheckEmailPasswords(context.Background(), &config.Config{}, nil) {
			if f.Check == "email_password_audit_incomplete" {
				return f
			}
		}
		t.Fatalf("no email_password_audit_incomplete for %d unsupported mailboxes", unsupported)
		return alert.Finding{}
	}
	assertSameHealthIdentity(t, run(3), run(1))
}

func TestAccountScanCheckPanicIdentityIgnoresStackTrace(t *testing.T) {
	run := func(name string) alert.Finding {
		check := namedCheck{name, func(context.Context, *config.Config, *state.Store) []alert.Finding {
			panic("crafted input")
		}}
		got := runAccountScanCheck(context.Background(), check, &config.Config{}, nil, time.Second)
		if len(got) != 1 || got[0].Check != "check_panic" {
			t.Fatalf("findings = %+v, want one check_panic", got)
		}
		return got[0]
	}
	first := run("boom")
	assertSameHealthIdentity(t, first, run("boom"))
	assertDistinctHealthIdentity(t, first, run("other_boom"))
}

// The findings page and the dismiss flow address a row by Key. A stable
// identity must still show the newest cycle's counts, leave no stale row, and
// let a dismissal outlive the next cycle's different counts.
func TestScanIncompleteLatestRowAndDismissSurviveCountChanges(t *testing.T) {
	build := func(n int) alert.Finding {
		g := newJSTaintGapCollector()
		for i := 0; i < n; i++ {
			g.record(fmt.Sprintf("/home/exampleuser/public_html/app-%d.js", i), "parse_error")
		}
		return g.finding()
	}
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	purge := []string{"js_taint_scan_incomplete"}

	first := build(314)
	st.Update([]alert.Finding{first})
	StoreLatestScanFindings(st, purge, []alert.Finding{first})
	second := build(45)
	st.Update([]alert.Finding{second})
	StoreLatestScanFindings(st, purge, []alert.Finding{second})

	latest := st.LatestFindings()
	if len(latest) != 1 || latest[0].Message != second.Message || latest[0].Key() != second.Key() {
		t.Fatalf("latest = %+v, want one row carrying the newest cycle", latest)
	}

	st.DismissFinding(latest[0].Key())
	st.DismissLatestFinding(latest[0].Key())
	if rows := st.LatestFindings(); len(rows) != 0 {
		t.Fatalf("dismissed row still listed: %+v", rows)
	}
	third := build(1241)
	if fresh := st.FilterNew([]alert.Finding{third}); len(fresh) != 0 {
		t.Fatalf("dismissed condition re-alerted after its counts changed: %+v", fresh)
	}
}
