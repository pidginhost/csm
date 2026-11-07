//go:build linux && yara

package checks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackcorpus"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/yara"
)

// corpusAccount owns every planted sample.
const corpusAccount = "corpus"

func TestAttackCorpusTier(t *testing.T) {
	useShippedScanEngines(t)
	attackcorpus.Drive(t, attackcorpus.Tier, runTierSample)
}

func TestAttackCorpusFullScan(t *testing.T) {
	useShippedScanEngines(t)
	attackcorpus.Drive(t, attackcorpus.FullScan, runFullScanSample)
}

// inProcessPHPTaint runs the analyzer in the test process. Production isolates
// it because the parser can loop on hostile input; corpus samples are curated
// and go test -timeout bounds a loop.
type inProcessPHPTaint struct{}

func (inProcessPHPTaint) Analyze(ctx context.Context, src []byte) phptaint.Report {
	return phptaint.Analyze(ctx, src)
}

// useShippedScanEngines installs what the daemon scans with: the shipped
// signature and YARA-X rules, the PHP taint analyzer and the zip lister. A
// missing or partly loaded engine fails the test, or a run would pass every
// sample only that engine catches.
func useShippedScanEngines(t *testing.T) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	configs := filepath.Join(filepath.Dir(file), "..", "..", "configs")

	sigs := signatures.NewScanner(configs)
	if err := sigs.LoadError(); err != nil || sigs.RuleCount() == 0 {
		t.Fatalf("signature rules from %s: %d loaded, error %v", configs, sigs.RuleCount(), err)
	}
	previousSigs := signatures.SetGlobal(sigs)
	t.Cleanup(func() { signatures.SetGlobal(previousSigs) })

	rules, err := yara.NewScanner(configs)
	if err != nil {
		t.Fatalf("YARA-X rules from %s: %v", configs, err)
	}
	if rules.RuleCount() == 0 {
		t.Fatalf("no YARA-X rules compiled from %s", configs)
	}
	previousYARA := yara.Active()
	yara.SetActive(rules)
	t.Cleanup(func() { yara.SetActive(previousYARA) })
	if b := activeYARABackend(); b == nil || b.RuleCount() != rules.RuleCount() {
		t.Fatal("the scan paths do not see the shipped YARA-X rules")
	}

	SetPHPTaintAnalyzer(inProcessPHPTaint{})
	t.Cleanup(func() { SetPHPTaintAnalyzer(nil) })
	if !phpTaintAnalyzerReady() {
		t.Fatal("PHP taint analyzer not ready")
	}
	// TestMain installs the in-process lister. Without one the phishing check
	// reports every kit zip as not checked.
	if currentZipLister() == nil {
		t.Fatal("no zip lister")
	}
}

// corpusScanErrors are findings that say a scan did not do its work on the
// tree: a panic, a timeout, a missing or truncated account, or content a
// scanner could not examine. A run with one did not test the sample.
var corpusScanErrors = map[string]bool{
	"check_panic":                       true,
	"check_timeout":                     true,
	"account_scan":                      true,
	"account_scan_truncated":            true,
	"db_content_scan_incomplete":        true,
	"yara_scan_incomplete":              true,
	"js_taint_scan_incomplete":          true,
	"php_taint_scan_incomplete":         true,
	phpIniIncompleteCheck:               true,
	"malware_companion_scan_incomplete": true,
}

func scanError(findings []alert.Finding) error {
	for _, f := range findings {
		if corpusScanErrors[f.Check] {
			return fmt.Errorf("%s: %s", f.Check, f.Message)
		}
	}
	return nil
}

// corpusSample is one sample's own account tree, cron spool, quarantine and
// state, with every package seam the scan paths read pointed at them.
type corpusSample struct {
	root, cronDir, quarantine string
	cfg                       *config.Config
	state                     *state.Store
	// queries and wpCLI count the database queries and wp-cli runs the
	// offline seams answered instead of the network.
	queries, wpCLI atomic.Int64
}

// networkAttempts is what the sample's seams kept off the network; Drive
// adds the requests that reached http.DefaultTransport.
func (c *corpusSample) networkAttempts() int64 { return c.queries.Load() + c.wpCLI.Load() }

// offlineCmd fails every command the way a missing binary does, so no host
// tool runs during a replay. Only wp-cli reaches the network (core checksum
// verification); the other command on these paths, cagefsctl in
// open_basedir, is a local query.
type offlineCmd struct{ wpCLI *atomic.Int64 }

func (o offlineCmd) refuse(name string) ([]byte, error) {
	if filepath.Base(name) == "wp" {
		o.wpCLI.Add(1)
	}
	return nil, &exec.Error{Name: name, Err: exec.ErrNotFound}
}

func (o offlineCmd) Run(name string, _ ...string) ([]byte, error) { return o.refuse(name) }

func (o offlineCmd) RunAllowNonZero(name string, _ ...string) ([]byte, error) {
	return o.refuse(name)
}

func (o offlineCmd) RunContext(_ context.Context, name string, _ ...string) ([]byte, error) {
	return o.refuse(name)
}

func (o offlineCmd) RunContextStdout(_ context.Context, name string, _ ...string) ([]byte, error) {
	return o.refuse(name)
}

func (o offlineCmd) RunWithEnv(name string, _ []string, _ ...string) ([]byte, error) {
	return o.refuse(name)
}

func (offlineCmd) LookPath(file string) (string, error) {
	return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
}

func newCorpusSample(t *testing.T) (*corpusSample, error) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		return nil, err
	}
	c := &corpusSample{
		root:       filepath.Join(base, "home"),
		cronDir:    filepath.Join(base, "cron"),
		quarantine: filepath.Join(base, "quarantine"),
	}
	stateDir := filepath.Join(base, "state")
	// A live account has its home and document root before any write. Modes
	// are set after creation so the umask cannot narrow them.
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{stateDir, 0o700}, {c.cronDir, 0o700},
		{c.root, 0o755}, {filepath.Join(c.root, corpusAccount), 0o755}, {filepath.Join(c.root, corpusAccount, "public_html"), 0o755},
	} {
		if err = os.Mkdir(d.path, d.mode); err == nil {
			err = os.Chmod(d.path, d.mode)
		}
		if err != nil {
			return nil, err
		}
	}
	if c.cfg, err = attackcorpus.Config(stateDir); err != nil {
		return nil, err
	}
	// The daemon keeps both stores in the state dir. Rolling content and
	// YARA cursors live in the database; without it the rolling pass is skipped.
	db, err := store.Open(stateDir)
	if err != nil {
		return nil, err
	}
	if c.state, err = state.Open(stateDir); err != nil {
		_ = db.Close()
		return nil, err
	}

	// The cPanel domain map lists the account, so map readers walk this tree
	// and never the host's real document roots.
	domains := filepath.Join(base, "userdatadomains")
	docroot := filepath.Join(c.root, corpusAccount, "public_html")
	if err = os.WriteFile(domains, []byte("example.com: "+corpusAccount+"==root==main==example.com=="+docroot+"\n"), 0o600); err != nil {
		_ = db.Close()
		return nil, err
	}

	withAccountHomeRoots(t, c.root)
	t.Cleanup(SetQuarantineDirForTest(c.quarantine))
	t.Cleanup(SetUserdataDomainsPathForTest(domains))
	withCompanionQueue(t)
	previousCron, previousCfg, previousDB := cronSpoolDir, config.Active(), store.Global()
	previousQuery, previousCmd := runMySQLQuery, cmdExec
	cronSpoolDir = func() string { return c.cronDir }
	// Remediation reads its allowed roots from the active config.
	config.SetActive(c.cfg)
	store.SetGlobal(db)
	// A query that ran and matched no rows: the database scans see an empty
	// site instead of dialing the host a sample's wp-config.php names.
	runMySQLQuery = func(wpDBCreds, string) []string {
		c.queries.Add(1)
		return nil
	}
	SetCmdRunner(offlineCmd{wpCLI: &c.wpCLI})
	t.Cleanup(func() {
		cronSpoolDir = previousCron
		config.SetActive(previousCfg)
		store.SetGlobal(previousDB)
		runMySQLQuery = previousQuery
		SetCmdRunner(previousCmd)
		_ = db.Close()
	})
	// The panel decides the web roots several checks walk. Pin the primary
	// target, not whatever runs the test.
	platform.ResetForTest()
	cpanel := platform.PanelCPanel
	platform.SetOverrides(platform.Overrides{Panel: &cpanel})
	t.Cleanup(platform.ResetForTest)
	return c, nil
}

func (c *corpusSample) plant(s attackcorpus.Sample) (map[string]string, map[string][]byte, error) {
	planted, err := s.Plant(c.root, c.cronDir, corpusAccount)
	if err != nil {
		return nil, nil, err
	}
	original := make(map[string][]byte, len(s.Files))
	for _, f := range s.Files {
		if original[f.Path], err = s.Content(f); err != nil {
			return nil, nil, err
		}
	}
	return planted, original, nil
}

// observe attributes a finding the way the responders find its file.
func (c *corpusSample) observe(f alert.Finding) attackcorpus.Observed {
	path := f.FilePath
	if path == "" {
		path = extractFilePath(f.Message)
	}
	return attackcorpus.ObservedFrom(f, attackcorpus.Attribute(path, c.root, c.cronDir, corpusAccount))
}

// runTierSample replays one sample through the scheduled deep tier: the file
// checks of deepChecks() through the production runner and its responders,
// as the daemon's deep scanner runs them.
func runTierSample(t *testing.T, s attackcorpus.Sample) attackcorpus.Outcome {
	c, err := newCorpusSample(t)
	if err != nil {
		return attackcorpus.Outcome{Err: err}
	}
	return c.replayTier(s)
}

// replayTier runs a baseline on the empty account with the same state first,
// so the planted files are new to the second run as they are to a periodic
// tier, and a host finding both runs raise is not taken for the sample's.
func (c *corpusSample) replayTier(s attackcorpus.Sample) attackcorpus.Outcome {
	fail := func(err error) attackcorpus.Outcome { return attackcorpus.Outcome{Err: err} }
	// The first file-index scan of a process walks everything and later ones
	// read changed directories. Restart the count so every sample gets the
	// same pair: a full baseline, then an incremental scan.
	previousScans := atomic.SwapInt32(&fileIndexScanCount, 0)
	defer atomic.StoreInt32(&fileIndexScanCount, previousScans)
	// php_content likewise skips rolling coverage every sixth host scan.
	previousContentScans := atomic.SwapInt32(&phpContentHostScanCount, 0)
	defer atomic.StoreInt32(&phpContentHostScanCount, previousContentScans)

	// A throttled check that ran in the baseline would be skipped by the
	// second run. Those checks only read document roots, which are empty
	// here, so the baseline has nothing of theirs to subtract.
	var unthrottled []namedCheck
	for _, nc := range attackCorpusTierChecks() {
		if _, throttled := checkThrottleMin[nc.name]; !throttled {
			unthrottled = append(unthrottled, nc)
		}
	}
	baseline, err := c.tier(unthrottled)
	if err != nil {
		return fail(fmt.Errorf("baseline: %w", err))
	}
	if entries, readErr := os.ReadDir(c.quarantine); len(entries) != 0 || (readErr != nil && !errors.Is(readErr, fs.ErrNotExist)) {
		return fail(fmt.Errorf("baseline on an empty account quarantined %d entries, %v", len(entries), readErr))
	}
	planted, original, err := c.plant(s)
	if err != nil {
		return fail(err)
	}
	after, err := c.tier(attackCorpusTierChecks())
	if err != nil {
		return fail(err)
	}

	remediation, cleaned, err := attackcorpus.ObserveRemediation(planted, original, c.quarantine)
	if err != nil {
		return fail(err)
	}
	return attackcorpus.Outcome{
		Findings: c.sinceBaseline(baseline, after), Remediation: remediation, CleanedSHA256: cleaned,
		NetworkAttempts: c.networkAttempts(),
	}
}

// tier runs the given deep checks once through the production runner. A
// check the run lists incomplete (throttled, timed out, panicked or short of
// its tree) did not examine the sample, and neither did a run with a scan
// error finding.
func (c *corpusSample) tier(checks []namedCheck) ([]alert.Finding, error) {
	ctx, gaps := WithCoverageGaps(context.Background())
	findings, _ := runParallelWithContext(ctx, c.cfg, c.state, checks, string(TierDeep), false)
	if incomplete := gaps.Snapshot().IncompleteChecks; len(incomplete) != 0 {
		return nil, fmt.Errorf("incomplete: %v", slices.Sorted(maps.Keys(incomplete)))
	}
	return findings, scanError(findings)
}

// sinceBaseline drops from after only the unattributed findings the baseline
// raised with the same check and message: those are about the host, not the
// sample. Any other unattributed finding stays, and Judge counts it as an
// error on a control.
func (c *corpusSample) sinceBaseline(baseline, after []alert.Finding) []attackcorpus.Observed {
	var findings []attackcorpus.Observed
	for _, f := range after {
		o := c.observe(f)
		if o.File == "" && slices.ContainsFunc(baseline, func(b alert.Finding) bool { return b.Check == f.Check && b.Message == f.Message }) {
			continue
		}
		findings = append(findings, o)
	}
	return findings
}

// runFullScanSample replays one sample through the operator full account
// scan with quarantine on: the scan job's runner, then its quarantine step.
func runFullScanSample(t *testing.T, s attackcorpus.Sample) attackcorpus.Outcome {
	c, err := newCorpusSample(t)
	if err != nil {
		return attackcorpus.Outcome{Err: err}
	}
	return c.replayFullScan(t, s)
}

// replayFullScan reports a scan cut short through check_panic and
// check_timeout findings only: the account runner keeps no completion record,
// so there is no coverage handle to read as the tier has.
func (c *corpusSample) replayFullScan(t *testing.T, s attackcorpus.Sample) attackcorpus.Outcome {
	fail := func(err error) attackcorpus.Outcome { return attackcorpus.Outcome{Err: err} }
	planted, original, err := c.plant(s)
	if err != nil {
		return fail(err)
	}
	// The job passes the daemon's state store (defaultScanRunner, scanjob.go).
	scanned := RunAccountScanWithOptions(context.Background(), c.cfg, c.state, corpusAccount, FullScanOptions(c.cfg, false))
	if err = scanError(scanned); err != nil {
		return fail(err)
	}
	quarantineAsScanJob(t, scanned)

	findings := make([]attackcorpus.Observed, 0, len(scanned))
	for _, f := range scanned {
		findings = append(findings, c.observe(f))
	}
	remediation, cleaned, err := attackcorpus.ObserveRemediation(planted, original, c.quarantine)
	if err != nil {
		return fail(err)
	}
	return attackcorpus.Outcome{Findings: findings, Remediation: remediation, CleanedSHA256: cleaned, NetworkAttempts: c.networkAttempts()}
}

// quarantineAsScanJob is the loop ScanJobManager.annotateQuarantine
// (internal/daemon/scanjob.go:681-720) runs for an uncancelled job with its
// quarantine flag set: every finding in order, a file this job already
// remediated is not acted on again, an ineligible finding is left for review
// and a failure is recorded but does not stop the job. Keep the two in step.
// The job acts only on findings under its stored-findings cap of 10000, which
// one account tree stays far below.
func quarantineAsScanJob(t *testing.T, findings []alert.Finding) {
	remediated := map[string]bool{}
	for _, f := range findings {
		if remediated[f.FilePath] && f.FilePath != "" {
			continue
		}
		result, eligible := QuarantineFindingFile(f)
		switch {
		case !eligible:
		case result.Success:
			remediated[f.FilePath] = true
		default:
			t.Logf("quarantine of %s failed: %s", f.FilePath, result.Error)
		}
	}
}

const (
	corpusShell      = "public_html/wp-content/uploads/2026/11/cache.php"
	corpusNamedShell = "public_html/wp-content/uploads/2026/11/wso.php"
	corpusPlugin     = "public_html/wp-content/plugins/example-widget/example-widget.php"
)

// corpusDriverWant is what both scan paths do with each driver sample. Every
// finding must name the sample's file, and a control must raise none.
var corpusDriverWant = map[string]struct {
	file, check string
	remediation attackcorpus.Remediation
}{
	// The shipped YARA rules match this shell on both paths, but neither path
	// moves it: a scheduled YARA match is not a quarantine trigger, and the
	// content heuristic rates the file High, below the Critical both
	// responders need. The realtime path quarantines it.
	"uploads_request_eval": {corpusShell, "yara_match_scheduled", attackcorpus.Untouched},
	// A known shell name is Critical by itself, so this sample drives the
	// quarantine step and its observation.
	"uploads_named_shell": {corpusNamedShell, "webshell", attackcorpus.Quarantined},
	"plugin_control":      {corpusPlugin, "", attackcorpus.Untouched},
}

// The drivers must work before any corpus relies on them: web shells in
// uploads are reported on their own paths and remediated as the path does,
// and a plain plugin raises nothing and is left alone.
func TestAttackCorpusTierDriver(t *testing.T) {
	testScanDriver(t, attackcorpus.Tier, runTierSample)
}

func TestAttackCorpusFullScanDriver(t *testing.T) {
	testScanDriver(t, attackcorpus.FullScan, runFullScanSample)
}

func testScanDriver(t *testing.T, p attackcorpus.Path, run func(*testing.T, attackcorpus.Sample) attackcorpus.Outcome) {
	useShippedScanEngines(t)
	attempts := attackcorpus.Offline(t)

	dir := t.TempDir()
	for name, w := range corpusDriverWant {
		kind, selftest, realtime := "malicious", "webshell_request_eval", `{"gap": "not driven by this test"}`
		scan := fmt.Sprintf(`{"findings": [{"check": %q, "file": %q, "min_severity": "critical"}], "remediation": {%[2]q: %q}}`, w.check, w.file, w.remediation)
		if w.check == "" {
			kind, selftest, realtime, scan = "control", "benign_wordpress_plugin", "{}", "{}"
		}
		writeCorpusManifest(t, dir, name, fmt.Sprintf(`{
			"name": %q, "category": "webshell", "kind": %q, "source": "fixture",
			"description": "scan driver self-test", "provenance": "self-test bundle",
			"files": [{"path": %q, "selftest": %q}],
			"expect": {"realtime": %s, "tier": %s, "fullscan": %[6]s}}`, name, kind, w.file, selftest, realtime, scan))
	}
	samples, err := attackcorpus.Load(dir, "private")
	if err != nil || len(samples) != len(corpusDriverWant) {
		t.Fatalf("Load = %d samples, %v; want %d", len(samples), err, len(corpusDriverWant))
	}

	for _, s := range samples {
		w := corpusDriverWant[s.Name]
		goroutines := runtime.NumGoroutine()
		t.Run(s.Name, func(t *testing.T) {
			o := run(t, s)
			// The JSON form leaves out finding text, which can quote sample bytes.
			observed, _ := json.Marshal(o.Findings)
			if o.Err != nil {
				t.Fatalf("driver error: %v", o.Err)
			}
			for _, f := range o.Findings {
				if f.File != w.file {
					t.Errorf("%s attributed to %q, want %s: %s", f.Check, f.File, w.file, observed)
				}
			}
			if w.check == "" && len(o.Findings) != 0 {
				t.Errorf("control findings: %s", observed)
			}
			if w.check != "" && !slices.ContainsFunc(o.Findings, func(f attackcorpus.Observed) bool {
				return f.Check == w.check && f.Severity == alert.Critical
			}) {
				t.Errorf("no Critical %s on %s: %s", w.check, w.file, observed)
			}
			if o.Remediation[w.file] != w.remediation {
				t.Errorf("%s is %s, want %s", w.file, o.Remediation[w.file], w.remediation)
			}
			if o.NetworkAttempts != 0 {
				t.Errorf("%d database or wp-cli attempts, want none", o.NetworkAttempts)
			}
			if r := attackcorpus.Judge(s, p, o); !r.Pass {
				t.Errorf("judge: %v", r.Failures)
			}
		})
		// The runner returns once its workers signal done, a moment before
		// those goroutines exit, so wait a bounded time for them to finish.
		for deadline := time.Now().Add(5 * time.Second); runtime.NumGoroutine() > goroutines && time.Now().Before(deadline); {
			time.Sleep(20 * time.Millisecond)
		}
		if n := runtime.NumGoroutine() - goroutines; n > 0 {
			t.Errorf("%s left %d goroutines running", s.Name, n)
		}
	}
	if n := attempts.Load(); n != 0 {
		t.Errorf("%d network attempts, want none", n)
	}
}

// Every sixth host scan in a process, php_content rereads its fixed
// directories and skips rolling coverage, which is the only tier pass that
// reaches PHP elsewhere in a doc root. A replay must not depend on how many
// scans ran before it. YARA misses this loader (the self-test bundle records
// the gap), so only rolling coverage can report it.
func TestAttackCorpusTierPinsPHPContentCadence(t *testing.T) {
	useShippedScanEngines(t)
	attackcorpus.Offline(t)
	const loader = "public_html/wp-content/cache/object/loader.php"
	dir := t.TempDir()
	writeCorpusManifest(t, dir, "rolling_only", fmt.Sprintf(`{
		"name": "rolling_only", "category": "webshell", "kind": "malicious", "source": "fixture",
		"description": "a loader outside the fixed php_content directories", "provenance": "self-test bundle",
		"files": [{"path": %q, "selftest": "obfuscated_base64_loader"}],
		"expect": {"realtime": {"gap": "not driven by this test"}, "tier": {"gap": "not driven by this test"}, "fullscan": {"gap": "not driven by this test"}}}`, loader))
	samples, err := attackcorpus.Load(dir, "private")
	if err != nil || len(samples) != 1 {
		t.Fatalf("Load = %d samples, %v; want 1", len(samples), err)
	}
	// Left alone, the baseline and the planted run are the fifth and sixth.
	previous := atomic.SwapInt32(&phpContentHostScanCount, 4)
	t.Cleanup(func() { atomic.StoreInt32(&phpContentHostScanCount, previous) })

	o := runTierSample(t, samples[0])
	observed, _ := json.Marshal(o.Findings)
	if o.Err != nil {
		t.Fatalf("driver error: %v", o.Err)
	}
	if !slices.ContainsFunc(o.Findings, func(f attackcorpus.Observed) bool { return f.File == loader }) {
		t.Errorf("rolling coverage did not reach %s: %s", loader, observed)
	}
	if got := atomic.LoadInt32(&phpContentHostScanCount); got != 4 {
		t.Errorf("php_content scan count = %d after the replay, want 4 restored", got)
	}
}

// A throttled check skipped by the run is reported, not taken for a clean
// result: the first run stamps every throttled check, so a second run at once
// skips them.
func TestAttackCorpusTierThrottledCheckFails(t *testing.T) {
	useShippedScanEngines(t)
	c, err := newCorpusSample(t)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.tier(attackCorpusTierChecks()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	_, err = c.tier(attackCorpusTierChecks())
	if err == nil {
		t.Fatal("a run that skipped throttled checks passed")
	}
	for _, name := range []string{"perf_error_logs", "perf_wp_config", "perf_wp_cron"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name throttled %s", err, name)
		}
	}
	if strings.Contains(err.Error(), "yara_deep") {
		t.Errorf("error %q names a check that ran", err)
	}
}

// corpusWPConfig names a database host and harmless credentials.
const corpusWPConfig = `<?php
define( 'DB_NAME', 'corpus_wp' );
define( 'DB_USER', 'corpus_wp' );
define( 'DB_PASSWORD', 'not-a-real-password' );
define( 'DB_HOST', '192.0.2.1' );
define( 'DB_CHARSET', 'utf8mb4' );
$table_prefix = 'wp_';
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';
`

// A WordPress config is ordinary site content, so it is a control. Its
// database host and the WordPress checksum service must never be reached:
// the full scan's database scan and core verification ask through seams that
// answer offline, and the tier runs neither.
func TestAttackCorpusScansServeHostLookupsOffline(t *testing.T) {
	useShippedScanEngines(t)
	attempts := attackcorpus.Offline(t)
	dir := t.TempDir()
	writeCorpusManifest(t, dir, "wp_config_control", `{
		"name": "wp_config_control", "category": "webshell", "kind": "control", "source": "synthetic",
		"description": "a WordPress config naming a database host", "provenance": "written for the driver test",
		"files": [{"path": "public_html/wp-config.php", "b64": "wp-config.php.b64"}],
		"expect": {"realtime": {}, "tier": {}, "fullscan": {}}}`)
	encoded := base64.StdEncoding.EncodeToString([]byte(corpusWPConfig))
	if err := os.WriteFile(filepath.Join(dir, "webshell", "wp_config_control", "wp-config.php.b64"), []byte(encoded), 0o644); err != nil {
		t.Fatal(err)
	}
	samples, err := attackcorpus.Load(dir, "private")
	if err != nil || len(samples) != 1 {
		t.Fatalf("Load = %d samples, %v; want 1", len(samples), err)
	}

	for _, d := range []struct {
		path      attackcorpus.Path
		run       func(*testing.T, *corpusSample, attackcorpus.Sample) attackcorpus.Outcome
		reachesDB bool
	}{
		{attackcorpus.Tier, func(_ *testing.T, c *corpusSample, s attackcorpus.Sample) attackcorpus.Outcome {
			return c.replayTier(s)
		}, false},
		{attackcorpus.FullScan, func(t *testing.T, c *corpusSample, s attackcorpus.Sample) attackcorpus.Outcome {
			return c.replayFullScan(t, s)
		}, true},
	} {
		t.Run(string(d.path), func(t *testing.T) {
			c, err := newCorpusSample(t)
			if err != nil {
				t.Fatal(err)
			}
			o := d.run(t, c, samples[0])
			observed, _ := json.Marshal(o.Findings)
			if o.Err != nil {
				t.Fatalf("driver error: %v", o.Err)
			}
			if q, w := c.queries.Load(), c.wpCLI.Load(); (q > 0) != d.reachesDB || (w > 0) != d.reachesDB {
				t.Errorf("%d queries and %d wp-cli runs answered offline, want both nonzero: %v", q, w, d.reachesDB)
			}
			if o.NetworkAttempts != c.networkAttempts() {
				t.Errorf("outcome reports %d attempts, seams counted %d", o.NetworkAttempts, c.networkAttempts())
			}
			if r := attackcorpus.Judge(samples[0], d.path, o); !r.Pass {
				t.Errorf("judge: %v; findings %s", r.Failures, observed)
			}
		})
	}
	if n := attempts.Load(); n != 0 {
		t.Errorf("%d requests reached http.DefaultTransport, want none", n)
	}
}

// Only an unattributed finding the baseline raised with the same check and
// message is dropped; a finding on a sample file is kept even then.
func TestAttackCorpusTierBaselineSubtraction(t *testing.T) {
	withAccountHomeRoots(t, "/srv/home")
	c := &corpusSample{root: "/srv/home", cronDir: "/srv/cron"}
	host := alert.Finding{Check: "suspicious_file", Message: "Suspicious hidden file: /tmp/.a"}
	shell := alert.Finding{Check: "webshell", Message: "Webshell file found: /srv/home/corpus/public_html/c99.php"}
	after := []alert.Finding{
		host,
		{Check: "suspicious_file", Message: "Suspicious hidden file: /tmp/.b"},
		{Check: "check_summary", Message: "Suspicious hidden file: /tmp/.a"},
		shell,
	}
	got := c.sinceBaseline([]alert.Finding{host, shell}, after)
	var kept []string
	for _, o := range got {
		kept = append(kept, o.Check+" "+o.File)
	}
	want := []string{"suspicious_file ", "check_summary ", "webshell public_html/c99.php"}
	if !slices.Equal(kept, want) {
		t.Fatalf("kept %q, want %q", kept, want)
	}
}

func writeCorpusManifest(t *testing.T, corpus, name, manifest string) {
	t.Helper()
	dir := filepath.Join(corpus, "webshell", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sample.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
}
