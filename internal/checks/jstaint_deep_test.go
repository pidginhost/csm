package checks

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/jstaint"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/yara"
)

// useNilYARABackend simulates a host with no compiled YARA rules while YARA
// support is reported unavailable, so the nil-backend path emits no High
// finding noise into assertions about the JS consumer. The returned restore
// lets a test bring the backend registry back mid-test; cleanup still runs
// it at test end as a safety net.
func useNilYARABackend(t *testing.T) (restore func()) {
	t.Helper()
	prevBackend := activeYARABackend
	prevAvailable := yaraAvailable
	activeYARABackend = func() yara.Backend { return nil }
	yaraAvailable = func() bool { return false }
	restore = func() {
		activeYARABackend = prevBackend
		yaraAvailable = prevAvailable
	}
	t.Cleanup(restore)
	return restore
}

// countJSTaintAnalyze wraps the real analyzer and records the sources it saw.
func countJSTaintAnalyze(t *testing.T) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	prev := jsTaintAnalyze
	jsTaintAnalyze = func(ctx context.Context, src []byte) jstaint.Report {
		calls.Add(1)
		return jstaint.Analyze(ctx, src)
	}
	t.Cleanup(func() { jsTaintAnalyze = prev })
	return &calls
}

type openCountingOS struct {
	OS
	opens map[string]int
}

func (o *openCountingOS) Open(path string) (*os.File, error) {
	o.opens[path]++
	return o.OS.Open(path)
}

func jsFindingsByCheck(findings []alert.Finding, check string) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

func TestCheckYARADeepDetectsJSKeyloggerWithNilBackend(t *testing.T) {
	db := useRollingStore(t)
	useNilYARABackend(t)
	root := t.TempDir()
	path := writeYARADeepFile(t, root, "wp-content/probe.js", jsKeyloggerFixture)

	ctx, collector := withIncompleteCheckCollector(context.Background())
	findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, nil)

	got := jsFindingsByCheck(findings, "js_keylogger_dataflow")
	if len(got) != 1 {
		t.Fatalf("js findings = %+v, want exactly one", findings)
	}
	f := got[0]
	if f.FilePath != path || f.Severity != alert.Critical {
		t.Fatalf("finding = %+v, want Critical at %s", f, path)
	}
	wantSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(jsKeyloggerFixture)))
	if f.ContentSHA256 != wantSHA {
		t.Fatalf("ContentSHA256 = %q, want hash of analyzed bytes %q", f.ContentSHA256, wantSHA)
	}
	if !strings.Contains(f.DetectLogic, fmt.Sprintf("jstaint=%d", JSTaintLogicVersion)) {
		t.Fatalf("DetectLogic = %q, want jstaint component", f.DetectLogic)
	}
	if !strings.Contains(f.Details, "e.which") {
		t.Fatalf("Details = %q, want keystroke source property", f.Details)
	}
	if collector.contains("js_taint_deep") {
		t.Fatal("full JS cycle must complete so stale JS findings purge normally")
	}
	if !collector.contains("yara_deep") {
		t.Fatal("missing backend must keep the YARA owner incomplete")
	}
	cur, ok, err := db.GetScanCursor("", jsTaintDeepCursorCheck)
	if err != nil || !ok {
		t.Fatalf("js cursor after full run: ok=%v err=%v", ok, err)
	}
	if cur.LastPath != "" || cur.LastFullCycleTS.IsZero() {
		t.Fatalf("js cursor = %+v, want completed cycle", cur)
	}
	if _, ok, _ := db.GetScanCursor("", yaraDeepCursorCheck); ok {
		t.Fatal("missing backend must leave the YARA cursor unwritten")
	}
}

func TestCheckYARADeepRunsBothConsumersOnceOnSameSnapshot(t *testing.T) {
	useRollingStore(t)
	root := t.TempDir()
	path := writeYARADeepFile(t, root, "probe.js", jsKeyloggerFixture)

	backend := &recordingYARABackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	calls := countJSTaintAnalyze(t)
	fs := &openCountingOS{OS: realOS{}, opens: map[string]int{}}
	withMockOS(t, fs)

	findings := CheckYARADeep(context.Background(), &config.Config{AccountRoots: []string{root}}, nil)

	if len(backend.scanned) != 1 || backend.scanned[0] != jsKeyloggerFixture {
		t.Fatalf("backend scans = %q, want the one snapshot exactly once", backend.scanned)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("JS analyses = %d, want exactly 1", got)
	}
	if fs.opens[path] != 1 {
		t.Fatalf("file opened %d times, want one shared snapshot read", fs.opens[path])
	}
	if len(jsFindingsByCheck(findings, "js_keylogger_dataflow")) != 1 {
		t.Fatalf("findings = %+v, want the JS detection", findings)
	}
}

func TestCheckYARADeepLatestStateFollowsEachOwner(t *testing.T) {
	for _, tc := range []struct {
		name       string
		nilBackend bool
	}{
		{name: "backend-present"},
		{name: "nil-backend", nilBackend: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useRollingStore(t)
			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()

			root := t.TempDir()
			brokenPath := writeYARADeepFile(t, root, "broken.js", "keydown fetch ((((")
			cleanPath := writeYARADeepFile(t, root, "clean.js", jsCleanCandidateFixture)
			malPath := writeYARADeepFile(t, root, "mal.dat", "dormant malware")
			gonePath := filepath.Join(root, "gone.js")

			st.SetLatestFindings([]alert.Finding{
				{Check: "yara_match_scheduled", Severity: alert.Critical, Message: "prior YARA", FilePath: malPath},
				{Check: "js_keylogger_dataflow", Severity: alert.Critical, Message: "prior JS broken", FilePath: brokenPath},
				{Check: "js_keylogger_dataflow", Severity: alert.Critical, Message: "prior JS clean", FilePath: cleanPath},
				{Check: "js_keylogger_dataflow", Severity: alert.Critical, Message: "prior JS gone", FilePath: gonePath},
			})

			if tc.nilBackend {
				useNilYARABackend(t)
			} else {
				yara.SetActive(&deepYARATestBackend{})
				t.Cleanup(func() { yara.SetActive(nil) })
			}

			cfg := &config.Config{AccountRoots: []string{root}}
			check := namedCheck{name: "yara_deep", fn: CheckYARADeep}
			findings, purge := runParallelWithContext(context.Background(), cfg, st, []namedCheck{check}, "deep", true)

			incomplete := jsFindingsByCheck(findings, "js_taint_scan_incomplete")
			if len(incomplete) != 1 || !strings.Contains(incomplete[0].Details, "parse_error=1") {
				t.Fatalf("aggregate = %+v, want one parse_error entry", incomplete)
			}

			StoreLatestScanFindings(st, purge, findings)
			got := st.LatestFindings()

			var jsPaths []string
			for _, f := range got {
				if f.Check == "js_keylogger_dataflow" {
					jsPaths = append(jsPaths, f.FilePath)
				}
			}
			if len(jsPaths) != 1 || jsPaths[0] != brokenPath {
				t.Fatalf("surviving JS findings = %v, want only the parse-failure carry-forward %s", jsPaths, brokenPath)
			}
			hasYARA := containsFindingCheck(got, "yara_match_scheduled")
			if tc.nilBackend && !hasYARA {
				t.Fatal("nil backend must preserve prior YARA state via its incomplete owner")
			}
			if !tc.nilBackend && !hasYARA {
				t.Fatal("present backend re-detects the dormant file; finding must survive the purge")
			}
		})
	}
}

func TestCheckYARADeepForcedJSAdapterPanicStillRunsYARA(t *testing.T) {
	useRollingStore(t)
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	root := t.TempDir()
	malPath := writeYARADeepFile(t, root, "mal.dat", "dormant malware")
	st.SetLatestFindings([]alert.Finding{
		{Check: "js_keylogger_dataflow", Severity: alert.Critical, Message: "prior JS", FilePath: malPath},
	})

	yara.SetActive(&deepYARATestBackend{})
	t.Cleanup(func() { yara.SetActive(nil) })
	prev := jsTaintAnalyze
	jsTaintAnalyze = func(context.Context, []byte) jstaint.Report { panic("forced adapter panic") }
	t.Cleanup(func() { jsTaintAnalyze = prev })

	ctx, collector := withIncompleteCheckCollector(context.Background())
	findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, st)

	if len(jsFindingsByCheck(findings, "yara_match_scheduled")) != 1 {
		t.Fatalf("findings = %+v, want the YARA match despite the JS panic", findings)
	}
	incomplete := jsFindingsByCheck(findings, "js_taint_scan_incomplete")
	if len(incomplete) != 1 || !strings.Contains(incomplete[0].Details, "panic=1") {
		t.Fatalf("aggregate = %+v, want one panic entry", incomplete)
	}
	carried := jsFindingsByCheck(findings, "js_keylogger_dataflow")
	if len(carried) != 1 || carried[0].FilePath != malPath {
		t.Fatalf("carry-forward = %+v, want the prior finding at the panicked path", carried)
	}
	if collector.contains("js_taint_deep") {
		t.Fatal("a known-path JS gap must not mark the owner check-wide incomplete")
	}
}

func TestCheckYARADeepYARAErrorRetainsJSResult(t *testing.T) {
	useRollingStore(t)
	root := t.TempDir()
	writeYARADeepFile(t, root, "probe.js", jsKeyloggerFixture)

	yara.SetActive(&deepYARATestBackend{err: fmt.Errorf("worker unavailable")})
	t.Cleanup(func() { yara.SetActive(nil) })

	ctx, collector := withIncompleteCheckCollector(context.Background())
	findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, nil)

	if len(jsFindingsByCheck(findings, "js_keylogger_dataflow")) != 1 {
		t.Fatalf("findings = %+v, want the JS result despite the YARA error", findings)
	}
	if !containsFindingCheck(findings, "yara_scan_incomplete") {
		t.Fatalf("findings = %+v, want the YARA coverage gap", findings)
	}
	if !collector.contains("yara_deep") || collector.contains("js_taint_deep") {
		t.Fatal("YARA error marks only its own owner incomplete")
	}
}

func TestCheckYARADeepJSTaintHashStaysBoundToSharedSnapshotOnYARAFallback(t *testing.T) {
	useRollingStore(t)
	root := t.TempDir()
	path := writeYARADeepFile(t, root, "probe.js", jsKeyloggerFixture)
	workerSHA := strings.Repeat("a", sha256.Size*2)
	backend := &oversizeInlineBackend{scanFileSHA: workerSHA}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })

	findings := CheckYARADeep(context.Background(), &config.Config{AccountRoots: []string{root}}, nil)

	jsFindings := jsFindingsByCheck(findings, "js_keylogger_dataflow")
	if len(jsFindings) != 1 {
		t.Fatalf("JS findings = %+v, want one shared-snapshot detection", jsFindings)
	}
	wantSnapshotSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(jsKeyloggerFixture)))
	if jsFindings[0].FilePath != path || jsFindings[0].ContentSHA256 != wantSnapshotSHA {
		t.Fatalf("JS finding = %+v, want in-memory snapshot hash %q", jsFindings[0], wantSnapshotSHA)
	}
	yaraFindings := jsFindingsByCheck(findings, "yara_match_scheduled")
	if len(yaraFindings) != 1 || yaraFindings[0].ContentSHA256 != workerSHA {
		t.Fatalf("YARA findings = %+v, want path-worker hash %q", yaraFindings, workerSHA)
	}
}

func TestCheckYARADeepDivergentCursorsScanIndependentRanges(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	pathA := writeYARADeepFile(t, root, "a.js", "//a\n"+jsCleanCandidateFixture)
	pathB := writeYARADeepFile(t, root, "b.js", "//b\n"+jsCleanCandidateFixture)
	pathC := writeYARADeepFile(t, root, "c.js", "//c\n"+jsCleanCandidateFixture)
	var jsCursor store.ScanCursorRecord
	jsCursor.Check = jsTaintDeepCursorCheck
	jsCursor.LastPath = pathB
	jsCursor.WrappedAt = time.Now().UTC()
	if err := db.PutScanCursor(jsCursor); err != nil {
		t.Fatal(err)
	}

	backend := &recordingYARABackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	var analyzed []string
	prev := jsTaintAnalyze
	jsTaintAnalyze = func(ctx context.Context, src []byte) jstaint.Report {
		analyzed = append(analyzed, string(src[:4]))
		return jstaint.Analyze(ctx, src)
	}
	t.Cleanup(func() { jsTaintAnalyze = prev })
	fs := &openCountingOS{OS: realOS{}, opens: map[string]int{}}
	withMockOS(t, fs)

	ctx, collector := withIncompleteCheckCollector(context.Background())
	CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, nil)

	if len(backend.scanned) != 3 {
		t.Fatalf("backend scanned %d snapshots, want its whole 3-file cycle", len(backend.scanned))
	}
	if len(analyzed) != 1 || analyzed[0] != "//c\n" {
		t.Fatalf("JS analyzed %v, want only the file past its own cursor", analyzed)
	}
	for _, p := range []string{pathA, pathB, pathC} {
		if fs.opens[p] != 1 {
			t.Fatalf("%s opened %d times, want one shared read per file", p, fs.opens[p])
		}
	}
	// The JS window resumed mid-cycle, so only the JS owner stays partial.
	if !collector.contains("js_taint_deep") || collector.contains("yara_deep") {
		t.Fatal("resumed JS window must mark only the JS owner incomplete")
	}
	for _, name := range []string{yaraDeepCursorCheck, jsTaintDeepCursorCheck} {
		cur, ok, err := db.GetScanCursor("", name)
		if err != nil || !ok {
			t.Fatalf("%s cursor: ok=%v err=%v", name, ok, err)
		}
		if cur.LastPath != "" || cur.LastFullCycleTS.IsZero() {
			t.Fatalf("%s cursor = %+v, want completed cycle", name, cur)
		}
	}
}

func TestCheckYARADeepBackendRecoveryRescansOwnRange(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	writeYARADeepFile(t, root, "a.js", "//a\n"+jsCleanCandidateFixture)
	writeYARADeepFile(t, root, "b.js", "//b\n"+jsCleanCandidateFixture)
	cfg := &config.Config{AccountRoots: []string{root}}

	restore := useNilYARABackend(t)
	CheckYARADeep(context.Background(), cfg, nil)
	if _, ok, _ := db.GetScanCursor("", yaraDeepCursorCheck); ok {
		t.Fatal("nil-backend run must not create a YARA cursor")
	}
	jsCur, ok, err := db.GetScanCursor("", jsTaintDeepCursorCheck)
	if err != nil || !ok || jsCur.LastFullCycleTS.IsZero() {
		t.Fatalf("js cursor after nil-backend run = %+v ok=%v err=%v, want completed cycle", jsCur, ok, err)
	}

	restore()
	backend := &recordingYARABackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	CheckYARADeep(context.Background(), cfg, nil)

	if len(backend.scanned) != 2 {
		t.Fatalf("recovered backend scanned %d snapshots, want its full 2-file range", len(backend.scanned))
	}
}

func TestCheckYARADeepSoftDeadlinePersistsBothCursors(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a/one.dat", "mal one")
	writeYARADeepFile(t, root, "b/two.dat", "mal two")

	base := time.Now().Add(time.Hour)
	clock := base
	backend := &recordingYARABackend{onScan: func() { clock = clock.Add(2 * yaraDeepDeadlineMargin) }}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	useYARADeepClock(t, &clock)

	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin+time.Minute))
	defer cancel()
	ctx, collector := withIncompleteCheckCollector(ctx)

	CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, nil)

	if !collector.contains("yara_deep") || !collector.contains("js_taint_deep") {
		t.Fatal("a soft-deadline stop is a partial window for both owners")
	}
	for _, name := range []string{yaraDeepCursorCheck, jsTaintDeepCursorCheck} {
		cur, ok, err := db.GetScanCursor("", name)
		if err != nil || !ok {
			t.Fatalf("%s cursor: ok=%v err=%v", name, ok, err)
		}
		if cur.LastPath != first {
			t.Fatalf("%s cursor = %q, want the pre-deadline stop point %q", name, cur.LastPath, first)
		}
	}
}

func TestCheckYARADeepSizeGateDoesNotAdvanceOtherConsumerAtSoftDeadline(t *testing.T) {
	for _, tc := range []struct {
		name             string
		size             int
		configure        func(*config.Config)
		advancedConsumer string
	}{
		{
			name: "YARA gate leaves JS before the file",
			size: jstaint.MaxSourceBytes,
			configure: func(cfg *config.Config) {
				cfg.Thresholds.FullScanMaxFileMB = 1
			},
			advancedConsumer: yaraDeepCursorCheck,
		},
		{
			name:             "JS gate leaves YARA before the file",
			size:             jstaint.MaxSourceBytes + 1,
			configure:        func(*config.Config) {},
			advancedConsumer: jsTaintDeepCursorCheck,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := useRollingStore(t)
			root := t.TempDir()
			path := writeYARADeepFile(t, root, "oversize.dat", strings.Repeat("x", tc.size))
			cfg := &config.Config{AccountRoots: []string{root}}
			tc.configure(cfg)

			base := time.Now().Add(time.Hour)
			clock := base
			counter := &openCountingOS{OS: realOS{}, opens: map[string]int{}}
			fs := &faultingYARADeepOS{OS: counter}
			fs.lstat = func(gotPath string) (os.FileInfo, error) {
				info, err := fs.OS.Lstat(gotPath)
				if gotPath == path {
					clock = clock.Add(2 * yaraDeepDeadlineMargin)
				}
				return info, err
			}
			withMockOS(t, fs)
			useYARADeepClock(t, &clock)
			yara.SetActive(&recordingYARABackend{})
			t.Cleanup(func() { yara.SetActive(nil) })

			ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin+time.Minute))
			defer cancel()
			CheckYARADeep(ctx, cfg, nil)

			if counter.opens[path] != 0 {
				t.Fatalf("file opened %d time(s) after the soft deadline, want 0", counter.opens[path])
			}
			for _, name := range []string{yaraDeepCursorCheck, jsTaintDeepCursorCheck} {
				cur, ok, err := db.GetScanCursor("", name)
				if err != nil || !ok {
					t.Fatalf("%s cursor: ok=%v err=%v", name, ok, err)
				}
				wantPath := ""
				if name == tc.advancedConsumer {
					wantPath = path
				}
				if cur.LastPath != wantPath {
					t.Fatalf("%s cursor = %q, want %q", name, cur.LastPath, wantPath)
				}
			}
		})
	}
}

func TestCheckYARADeepJSDisabledSkipsAnalysisAndResetsCursor(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	writeYARADeepFile(t, root, "probe.js", jsKeyloggerFixture)
	var seed store.ScanCursorRecord
	seed.Check = jsTaintDeepCursorCheck
	seed.LastPath = filepath.Join(root, "probe.js")
	if err := db.PutScanCursor(seed); err != nil {
		t.Fatal(err)
	}

	yara.SetActive(&recordingYARABackend{})
	t.Cleanup(func() { yara.SetActive(nil) })
	calls := countJSTaintAnalyze(t)

	cfg := &config.Config{AccountRoots: []string{root}}
	cfg.DisabledChecks = []string{"js_taint_deep"}
	ctx, collector := withIncompleteCheckCollector(context.Background())
	findings := CheckYARADeep(ctx, cfg, nil)

	if got := calls.Load(); got != 0 {
		t.Fatalf("disabled JS consumer analyzed %d file(s), want 0", got)
	}
	if len(jsFindingsByCheck(findings, "js_keylogger_dataflow")) != 0 {
		t.Fatalf("findings = %+v, want no JS output while disabled", findings)
	}
	if collector.contains("js_taint_deep") {
		t.Fatal("a disabled consumer is not a coverage gap")
	}
	cur, ok, err := db.GetScanCursor("", jsTaintDeepCursorCheck)
	if err != nil || !ok {
		t.Fatalf("js cursor: ok=%v err=%v", ok, err)
	}
	if cur.LastPath != "" || !cur.WrappedAt.IsZero() || !cur.LastFullCycleTS.IsZero() {
		t.Fatalf("js cursor = %+v, want reset so re-enabling starts a full cycle", cur)
	}
}

func TestCheckYARADeepYARADisabledSkipsBackendAndResetsCursor(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	path := writeYARADeepFile(t, root, "probe.js", jsKeyloggerFixture)
	var seed store.ScanCursorRecord
	seed.Check = yaraDeepCursorCheck
	seed.LastPath = path
	if err := db.PutScanCursor(seed); err != nil {
		t.Fatal(err)
	}

	backend := &recordingYARABackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })

	cfg := &config.Config{AccountRoots: []string{root}}
	cfg.DisabledChecks = []string{"yara_match_scheduled"}
	ctx, collector := withIncompleteCheckCollector(context.Background())
	findings := CheckYARADeep(ctx, cfg, nil)

	if len(backend.scanned) != 0 {
		t.Fatalf("disabled YARA consumer scanned %d snapshot(s), want 0", len(backend.scanned))
	}
	if len(jsFindingsByCheck(findings, "js_keylogger_dataflow")) != 1 {
		t.Fatalf("findings = %+v, want the JS detection to keep running", findings)
	}
	if containsFindingCheck(findings, "yara_scan_incomplete") || collector.contains("yara_deep") {
		t.Fatal("a deliberately disabled consumer is not a coverage gap")
	}
	cur, ok, err := db.GetScanCursor("", yaraDeepCursorCheck)
	if err != nil || !ok {
		t.Fatalf("yara cursor: ok=%v err=%v", ok, err)
	}
	if cur.LastPath != "" || !cur.WrappedAt.IsZero() || !cur.LastFullCycleTS.IsZero() {
		t.Fatalf("yara cursor = %+v, want reset so re-enabling starts a full cycle", cur)
	}
}

func TestCheckYARADeepJSOversizeGapCarriesForward(t *testing.T) {
	useRollingStore(t)
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	root := t.TempDir()
	bigPath := writeYARADeepFile(t, root, "big.js", strings.Repeat("+", jstaint.MaxSourceBytes+1))
	st.SetLatestFindings([]alert.Finding{
		{Check: "js_keylogger_dataflow", Severity: alert.Critical, Message: "prior JS big", FilePath: bigPath},
	})

	backend := &recordingYARABackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	calls := countJSTaintAnalyze(t)

	ctx, collector := withIncompleteCheckCollector(context.Background())
	findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, st)

	if got := calls.Load(); got != 0 {
		t.Fatalf("oversize file reached the analyzer %d time(s), want metadata-only rejection", got)
	}
	if len(backend.scanned) != 1 {
		t.Fatalf("backend scanned %d snapshot(s), want the oversize-for-JS file", len(backend.scanned))
	}
	incomplete := jsFindingsByCheck(findings, "js_taint_scan_incomplete")
	if len(incomplete) != 1 || !strings.Contains(incomplete[0].Details, "oversize=1") {
		t.Fatalf("aggregate = %+v, want one oversize entry", incomplete)
	}
	carried := jsFindingsByCheck(findings, "js_keylogger_dataflow")
	if len(carried) != 1 || carried[0].FilePath != bigPath {
		t.Fatalf("carry-forward = %+v, want the prior finding at the oversize path", carried)
	}
	if collector.contains("js_taint_deep") {
		t.Fatal("a known-path oversize gap must not mark the owner check-wide incomplete")
	}
}

func TestCheckYARADeepCarriesOnlyNewestPriorJSTaintFindingPerGapPath(t *testing.T) {
	useRollingStore(t)
	useNilYARABackend(t)
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	root := t.TempDir()
	brokenPath := writeYARADeepFile(t, root, "broken.js", "keydown fetch ((((")
	now := time.Now().UTC()
	st.SetLatestFindings([]alert.Finding{
		{Check: "js_keylogger_dataflow", Severity: alert.Critical, Message: "older prior", FilePath: brokenPath, Timestamp: now.Add(-time.Hour)},
		{Check: "js_keylogger_dataflow", Severity: alert.Critical, Message: "newer prior", FilePath: brokenPath, Timestamp: now},
	})

	findings := CheckYARADeep(context.Background(), &config.Config{AccountRoots: []string{root}}, st)

	carried := jsFindingsByCheck(findings, "js_keylogger_dataflow")
	if len(carried) != 1 || carried[0].Message != "newer prior" {
		t.Fatalf("carry-forward = %+v, want only the newest prior finding for %s", carried, brokenPath)
	}
}

func TestCheckYARADeepHardCancelLeavesBothCursors(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a/one.dat", "mal one")
	putYARADeepCursor(t, db, first, time.Now().UTC())
	var jsSeed store.ScanCursorRecord
	jsSeed.Check = jsTaintDeepCursorCheck
	jsSeed.LastPath = first
	if err := db.PutScanCursor(jsSeed); err != nil {
		t.Fatal(err)
	}

	yara.SetActive(&recordingYARABackend{})
	t.Cleanup(func() { yara.SetActive(nil) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, nil)

	if findings != nil {
		t.Fatalf("hard-canceled run returned findings the runner would drop: %+v", findings)
	}
	for _, name := range []string{yaraDeepCursorCheck, jsTaintDeepCursorCheck} {
		cur, ok, err := db.GetScanCursor("", name)
		if err != nil || !ok || cur.LastPath != first {
			t.Fatalf("hard cancel disturbed %s cursor: %+v ok=%v err=%v", name, cur, ok, err)
		}
	}
}

func TestCheckYARADeepHardCancelDoesNotResetDisabledConsumerCursor(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	path := writeYARADeepFile(t, root, "probe.js", jsKeyloggerFixture)
	wrappedAt := time.Now().UTC().Add(-time.Hour)
	lastFullCycle := wrappedAt.Add(-time.Hour)

	for _, name := range []string{yaraDeepCursorCheck, jsTaintDeepCursorCheck} {
		var seed store.ScanCursorRecord
		seed.Check = name
		seed.LastPath = path
		seed.WrappedAt = wrappedAt
		seed.LastFullCycleTS = lastFullCycle
		if err := db.PutScanCursor(seed); err != nil {
			t.Fatal(err)
		}
	}

	yara.SetActive(&recordingYARABackend{})
	t.Cleanup(func() { yara.SetActive(nil) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings := CheckYARADeep(ctx, &config.Config{
		AccountRoots:   []string{root},
		DisabledChecks: []string{logicalOwnerJSTaintDeep},
	}, nil)

	if findings != nil {
		t.Fatalf("hard-canceled run returned findings the runner would drop: %+v", findings)
	}
	for _, name := range []string{yaraDeepCursorCheck, jsTaintDeepCursorCheck} {
		cur, ok, err := db.GetScanCursor("", name)
		if err != nil || !ok {
			t.Fatalf("%s cursor after hard cancel: ok=%v err=%v", name, ok, err)
		}
		if cur.LastPath != path || !cur.WrappedAt.Equal(wrappedAt) || !cur.LastFullCycleTS.Equal(lastFullCycle) {
			t.Fatalf("hard cancel disturbed %s cursor: %+v", name, cur)
		}
	}
}

func TestCheckYARADeepMidWalkHardCancelDoesNotResetDisabledConsumerCursor(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	path := writeYARADeepFile(t, root, "probe.dat", "mal payload")
	wrappedAt := time.Now().UTC().Add(-time.Hour)
	lastFullCycle := wrappedAt.Add(-time.Hour)
	var seed store.ScanCursorRecord
	seed.Check = jsTaintDeepCursorCheck
	seed.LastPath = path
	seed.WrappedAt = wrappedAt
	seed.LastFullCycleTS = lastFullCycle
	if err := db.PutScanCursor(seed); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	backend := &recordingYARABackend{onScan: cancel}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })

	findings := CheckYARADeep(ctx, &config.Config{
		AccountRoots:   []string{root},
		DisabledChecks: []string{logicalOwnerJSTaintDeep},
	}, nil)

	if findings != nil {
		t.Fatalf("hard-canceled run returned findings the runner would drop: %+v", findings)
	}
	if len(backend.scanned) != 1 {
		t.Fatalf("backend scanned %d snapshots, want cancellation during the first scan", len(backend.scanned))
	}
	cur, ok, err := db.GetScanCursor("", jsTaintDeepCursorCheck)
	if err != nil || !ok {
		t.Fatalf("JS cursor after hard cancel: ok=%v err=%v", ok, err)
	}
	if cur.LastPath != path || !cur.WrappedAt.Equal(wrappedAt) || !cur.LastFullCycleTS.Equal(lastFullCycle) {
		t.Fatalf("mid-walk hard cancel disturbed disabled JS cursor: %+v", cur)
	}
}
