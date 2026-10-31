//go:build linux

package yaraworker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/workerproc"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// helperLauncher starts the test binary as a worker in mode, counting
// launches. mode is read at each launch, so a test can change it.
type helperLauncher struct {
	mu       sync.Mutex
	mode     string
	launches atomic.Int32
}

func newHelper(mode string) *helperLauncher { return &helperLauncher{mode: mode} }

func (h *helperLauncher) setMode(mode string) {
	h.mu.Lock()
	h.mode = mode
	h.mu.Unlock()
}

func (h *helperLauncher) launch(ctx context.Context) (workerproc.Process, error) {
	h.launches.Add(1)
	h.mu.Lock()
	mode := h.mode
	h.mu.Unlock()
	env := append(os.Environ(), "CSM_YARA_HELPER="+mode)
	return workerproc.ExecLauncher(os.Args[0], nil, env)(ctx)
}

type backendFixture struct {
	b         *Backend
	dir       string
	scan      *helperLauncher
	compile   *helperLauncher
	failures  chan string
	disabled  []string
	compileFn workerproc.Launcher
	scanFn    workerproc.Launcher
	log       func(string, ...any)
}

func newBackend(t *testing.T, fx *backendFixture) *Backend {
	t.Helper()
	if fx.dir == "" {
		fx.dir = rulesDir(t, map[string]string{"rules.yar": "marker:evil\n"})
	}
	if fx.scan == nil {
		fx.scan = newHelper("worker")
	}
	if fx.compile == nil {
		fx.compile = newHelper("worker")
	}
	if fx.compileFn == nil {
		fx.compileFn = fx.compile.launch
	}
	if fx.scanFn == nil {
		fx.scanFn = fx.scan.launch
	}
	if fx.log == nil {
		fx.log = t.Logf
	}
	fx.failures = make(chan string, 64)
	b, err := NewBackend(BackendConfig{
		ScanLaunch:     fx.scanFn,
		CompileLaunch:  fx.compileFn,
		RulesDir:       fx.dir,
		DisabledRules:  fx.disabled,
		ScanTimeout:    10 * time.Second,
		LoadTimeout:    10 * time.Second,
		CompileTimeout: 10 * time.Second,
		OnFailure: func(reason string, _ error) {
			select {
			case fx.failures <- reason:
			default:
			}
		},
		Log: fx.log,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Stop() })
	fx.b = b
	return b
}

func rulesDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "rules")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, text := range files {
		writeRule(t, dir, name, text)
	}
	return dir
}

func writeRule(t *testing.T, dir, name, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func ruleNames(t *testing.T, b *Backend, data string) []string {
	t.Helper()
	matches, err := b.ScanBytesChecked([]byte(data))
	if err != nil {
		t.Fatalf("scan %q: %v", data, err)
	}
	var names []string
	for _, m := range matches {
		names = append(names, m.RuleName)
	}
	return names
}

func tempFile(t *testing.T, data string) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "content")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestReloadCompilesInWorkerAndScans(t *testing.T) {
	fx := &backendFixture{}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if b.RuleCount() != 1 || b.CompileError() != "" {
		t.Fatalf("RuleCount=%d CompileError=%q", b.RuleCount(), b.CompileError())
	}
	if got := ruleNames(t, b, "xx evil xx"); len(got) != 1 || got[0] != "evil" {
		t.Fatalf("byte scan = %v", got)
	}
	matches, err := b.ScanFDChecked(tempFile(t, "an evil file"), 12)
	if err != nil || len(matches) != 1 || matches[0].Meta["severity"] != "critical" {
		t.Fatalf("descriptor scan = %+v, %v", matches, err)
	}
	if got := ruleNames(t, b, "clean"); len(got) != 0 {
		t.Fatalf("clean scan = %v", got)
	}
	if n := fx.compile.launches.Load(); n != 1 {
		t.Fatalf("compile launches = %d, want 1", n)
	}
}

func TestReloadStripsDisabledRules(t *testing.T) {
	fx := &backendFixture{
		dir:      rulesDir(t, map[string]string{"rules.yar": "marker:other\nrule drop_me {\nmarker:evil\n}\n"}),
		disabled: []string{"drop_me"},
	}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := ruleNames(t, b, "evil"); len(got) != 0 {
		t.Fatalf("a disabled rule still matched: %v", got)
	}
	if got := ruleNames(t, b, "other"); len(got) != 1 {
		t.Fatalf("the kept rule did not match: %v", got)
	}
}

func TestReloadRetiresWorkerWithOldRules(t *testing.T) {
	fx := &backendFixture{}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := ruleNames(t, b, "evil"); len(got) != 1 {
		t.Fatalf("first scan = %v", got)
	}
	writeRule(t, fx.dir, "rules.yar", "marker:other\n")
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := ruleNames(t, b, "other"); len(got) != 1 || got[0] != "other" {
		t.Fatalf("scan after reload = %v, want the new rule", got)
	}
	if got := ruleNames(t, b, "evil"); len(got) != 0 {
		t.Fatalf("the old rule still matched after reload: %v", got)
	}
	if spawns := b.Stats().Spawns; spawns != 2 {
		t.Fatalf("spawns = %d, want 2: the reload must retire the first worker", spawns)
	}
	if n := fx.compile.launches.Load(); n != 2 {
		t.Fatalf("compile launches = %d, want 2", n)
	}
}

func TestFailedReloadKeepsOldRules(t *testing.T) {
	fx := &backendFixture{}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	writeRule(t, fx.dir, "rules.yar", "syntax error")
	err := b.Reload()
	if err == nil || !strings.Contains(err.Error(), "rules.yar") {
		t.Fatalf("reload error = %v, want one naming rules.yar", err)
	}
	if got := ruleNames(t, b, "evil"); len(got) != 1 {
		t.Fatalf("old rules lost after a failed reload: %v", got)
	}
	if b.CompileError() != "" || b.RuleCount() != 1 {
		t.Fatalf("CompileError=%q RuleCount=%d, want old rules kept", b.CompileError(), b.RuleCount())
	}
}

func TestReloadRecoversFromBadRules(t *testing.T) {
	fx := &backendFixture{dir: rulesDir(t, map[string]string{"rules.yar": "syntax error"})}
	b := newBackend(t, fx)
	if err := b.Reload(); err == nil {
		t.Fatal("bad rules compiled")
	}
	if b.CompileError() == "" {
		t.Fatal("a failed first compile left no compile error")
	}
	if m, err := b.ScanBytesChecked([]byte("evil")); err == nil {
		t.Fatalf("scan without rules after a failed compile read clean: %+v", m)
	}
	writeRule(t, fx.dir, "rules.yar", "marker:evil\n")
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if b.CompileError() != "" {
		t.Fatalf("CompileError=%q after recovery", b.CompileError())
	}
	if got := ruleNames(t, b, "evil"); len(got) != 1 {
		t.Fatalf("scan after recovery = %v", got)
	}
}

func TestRestartReloadsWithoutRecompiling(t *testing.T) {
	fx := &backendFixture{scan: newHelper("crash-on:boom")}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if m, err := b.ScanBytesChecked([]byte("boom")); err == nil {
		t.Fatalf("a scan whose worker died read clean: %+v", m)
	}
	if got := ruleNames(t, b, "evil"); len(got) != 1 {
		t.Fatalf("scan on the replacement worker = %v", got)
	}
	if n := fx.compile.launches.Load(); n != 1 {
		t.Fatalf("compile launches = %d, want 1: a restart must not recompile", n)
	}
	if n := fx.scan.launches.Load(); n != 2 {
		t.Fatalf("scan launches = %d, want 2", n)
	}
}

func TestLoadFailureFailsScansClosed(t *testing.T) {
	fx := &backendFixture{scan: newHelper("load-error")}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if m, err := b.ScanBytesChecked([]byte("evil")); err == nil {
		t.Fatalf("byte scan with unloadable rules read clean: %+v", m)
	}
	if m, err := b.ScanFDChecked(tempFile(t, "evil"), 4); err == nil {
		t.Fatalf("descriptor scan with unloadable rules read clean: %+v", m)
	}
	select {
	case reason := <-fx.failures:
		if reason != workerproc.ReasonSpawn {
			t.Fatalf("failure reason = %q, want %q", reason, workerproc.ReasonSpawn)
		}
	default:
		t.Fatal("a load failure was not reported")
	}
}

func TestScanWorkerCrashKeepsBreakerClosed(t *testing.T) {
	fx := &backendFixture{scan: newHelper("crash-on:boom")}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < workerproc.ConsecutiveFailureLimit+2; i++ {
		_, err := b.ScanBytesChecked([]byte("boom"))
		if err == nil {
			t.Fatalf("scan %d of crashing content read clean", i)
		}
		if errors.Is(err, workerproc.ErrBreakerOpen) {
			t.Fatalf("scan %d: content that kills the worker opened the breaker: %v", i, err)
		}
	}
	if got := ruleNames(t, b, "evil"); len(got) != 1 {
		t.Fatalf("scan after crashes = %v", got)
	}
}

func TestEmptyRulesDirByteScanIsClean(t *testing.T) {
	fx := &backendFixture{dir: rulesDir(t, nil)}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if m, err := b.ScanBytesChecked([]byte("evil")); err != nil || m != nil {
		t.Fatalf("byte scan with no rules = %+v, %v; want clean", m, err)
	}
	if _, err := b.ScanFDChecked(tempFile(t, "evil"), 4); err == nil {
		t.Fatal("a mail part scanned with no rules")
	}
	if fx.compile.launches.Load() != 0 || b.Stats().Spawns != 0 {
		t.Fatal("an empty rule set started a worker")
	}
}

func TestCompileWorkerUnavailableFailsClosed(t *testing.T) {
	fx := &backendFixture{compileFn: func(context.Context) (workerproc.Process, error) {
		return nil, errors.New("systemd-run unavailable")
	}}
	b := newBackend(t, fx)
	err := b.Reload()
	if err == nil || workerproc.FailureReason(err) != workerproc.ReasonSpawn {
		t.Fatalf("reload error = %v (reason %q), want a spawn failure", err, workerproc.FailureReason(err))
	}
	if m, err := b.ScanBytesChecked([]byte("evil")); err == nil {
		t.Fatalf("byte scan read clean while rules could not compile: %+v", m)
	}
	if _, err := b.ScanFDChecked(tempFile(t, "evil"), 4); err == nil {
		t.Fatal("descriptor scan read clean while rules could not compile")
	}
}

func TestCompileRejectsBadRulesDescriptor(t *testing.T) {
	for _, mode := range []string{"compile-nofd", "compile-huge", "compile-empty"} {
		t.Run(mode, func(t *testing.T) {
			fx := &backendFixture{}
			b := newBackend(t, fx)
			if err := b.Reload(); err != nil {
				t.Fatal(err)
			}
			fx.compile.setMode(mode)
			if err := b.Reload(); err == nil {
				t.Fatal("a bad compile reply was accepted")
			}
			if got := ruleNames(t, b, "evil"); len(got) != 1 || b.RuleCount() != 1 {
				t.Fatalf("kept rules changed: %v, count %d", got, b.RuleCount())
			}
		})
	}
}

func TestTestCompileLeavesRulesAlone(t *testing.T) {
	fx := &backendFixture{}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := b.TestCompile("marker:x\nmarker:y\n"); err != nil {
		t.Fatal(err)
	}
	if err := b.TestCompile("syntax error"); err == nil {
		t.Fatal("a broken source passed the compile test")
	}
	if err := b.TestCompile("no markers"); err == nil {
		t.Fatal("a source with no rules passed the compile test")
	}
	if b.RuleCount() != 1 {
		t.Fatalf("RuleCount = %d after compile tests, want 1", b.RuleCount())
	}
	if got := ruleNames(t, b, "x"); len(got) != 0 {
		t.Fatalf("a compile test changed the scanning rules: %v", got)
	}
}

func TestWarmStartsWorker(t *testing.T) {
	fx := &backendFixture{}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := b.Warm(); err != nil {
		t.Fatal(err)
	}
	if st := b.Stats(); !st.Running || st.Spawns != 1 {
		t.Fatalf("stats after warm = %+v", st)
	}
}

func TestScanFDSendsReadOnlyDescriptor(t *testing.T) {
	fx := &backendFixture{scan: newHelper("report-ro")}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ScanFDChecked(tempFile(t, "evil"), 4); err != nil {
		t.Fatalf("the worker got a writable descriptor: %v", err)
	}
}

type fakeProcess struct {
	oom    bool
	memory uint64
}

func (*fakeProcess) Conn() *net.UnixConn   { return nil }
func (*fakeProcess) Kill() error           { return nil }
func (*fakeProcess) Done() <-chan struct{} { return nil }
func (*fakeProcess) PID() int              { return 1 }
func (*fakeProcess) Retire() bool          { return false }
func (p *fakeProcess) OOMKilled() bool     { return p.oom }
func (p *fakeProcess) MemoryUsed() uint64  { return p.memory }

func TestLaunchWrapperForwardsOOM(t *testing.T) {
	var gen atomic.Uint64
	gen.Store(1)
	p := &rulesProcess{Process: &fakeProcess{oom: true, memory: 42}, gen: 1, current: &gen}
	if !p.OOMKilled() || p.MemoryUsed() != 42 {
		t.Fatalf("wrapper hid the inner process state: oom=%v memory=%d", p.OOMKilled(), p.MemoryUsed())
	}
	if p.Retire() {
		t.Fatal("a worker on the current rules asked to retire")
	}
	gen.Store(2)
	if !p.Retire() {
		t.Fatal("a worker on old rules did not retire")
	}
}

// A payload larger than one socket frame goes to the worker as a descriptor,
// so nothing refuses it on size. When the worker cannot start, that is a real
// scan failure and the scan path logs it once.
func TestScanBytesLargePayloadFailureIsLogged(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	fx := &backendFixture{
		scanFn: func(context.Context) (workerproc.Process, error) { return nil, errors.New("no unit") },
		log: func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			lines = append(lines, fmt.Sprintf(format, args...))
		},
	}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ScanBytesChecked(make([]byte, yaraipc.MaxFrameBytes+1)); err == nil {
		t.Fatal("scan with no worker succeeded")
	}
	mu.Lock()
	defer mu.Unlock()
	scanLines := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "scan: ") {
			scanLines++
		}
	}
	if scanLines != 1 {
		t.Errorf("scan failure logged %d times, want 1: %q", scanLines, lines)
	}
}

// Disabling every rule leaves a compiled set with no rules. It follows the
// empty-rule policy without a worker: byte scans are clean, mail parts are
// not scanned.
func TestZeroRuleSetFollowsEmptyPolicy(t *testing.T) {
	fx := &backendFixture{
		dir:      rulesDir(t, map[string]string{"rules.yar": "rule drop_me {\nmarker:evil\n}\n"}),
		disabled: []string{"drop_me"},
	}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if b.RuleCount() != 0 || b.CompileError() != "" {
		t.Fatalf("RuleCount=%d CompileError=%q", b.RuleCount(), b.CompileError())
	}
	if m, err := b.ScanBytesChecked([]byte("evil")); err != nil || m != nil {
		t.Fatalf("byte scan with every rule disabled = %+v, %v; want clean", m, err)
	}
	if _, err := b.ScanFDChecked(tempFile(t, "evil"), 4); err == nil {
		t.Fatal("a mail part scanned with every rule disabled")
	}
	if spawns := b.Stats().Spawns; spawns != 0 {
		t.Fatalf("spawns = %d, want 0: an empty rule set needs no worker", spawns)
	}
}

// A worker that never answers the load is killed at the load deadline, and
// the scan that started it fails instead of waiting forever.
func TestLoadTimeoutKillsHungWorker(t *testing.T) {
	fx := &backendFixture{scan: newHelper("load-hang")}
	b := newBackend(t, fx)
	b.cfg.LoadTimeout = 300 * time.Millisecond
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	if m, err := b.ScanBytesChecked([]byte("evil")); err == nil {
		t.Fatalf("scan on a worker that never loaded read clean: %+v", m)
	}
	if took := time.Since(began); took > 5*time.Second {
		t.Fatalf("scan waited %s for a hung load", took)
	}
	if b.Stats().Running {
		t.Fatal("a worker that never loaded was kept")
	}
}

func TestReloadInvalidatesVerdicts(t *testing.T) {
	b := newBackend(t, &backendFixture{})
	generation := yara.CacheGeneration()
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if yara.CacheGeneration() == generation {
		t.Fatal("a reload kept cached verdicts")
	}
}

// Zero bytes are clean without a round trip, even when rules failed to
// compile; a stopped backend still refuses them.
// Until a reload compiles the rules or finds the directory empty, no scan
// reads clean. A reload that ends with neither, such as one canceled at
// startup, leaves file scans failing closed.
func TestScansFailClosedUntilRulesConfirmed(t *testing.T) {
	b := newBackend(t, &backendFixture{})
	if m, err := b.ScanBytesChecked([]byte("evil")); err == nil {
		t.Fatalf("byte scan read clean before any reload: %+v", m)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.ReloadContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reload = %v, want context.Canceled", err)
	}
	if m, err := b.ScanBytesChecked([]byte("evil")); err == nil {
		t.Fatalf("byte scan read clean after a canceled reload: %+v", m)
	}
	if b.CompileError() == "" {
		t.Fatal("no compile error reported while no rules are loaded")
	}
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := b.CompileError(); got != "" {
		t.Fatalf("compile error %q kept after rules compiled", got)
	}
}

func TestScanBytesCheckedEmptyData(t *testing.T) {
	fx := &backendFixture{dir: rulesDir(t, map[string]string{"rules.yar": "syntax error"})}
	b := newBackend(t, fx)
	if err := b.Reload(); err == nil {
		t.Fatal("bad rules compiled")
	}
	if _, err := b.ScanBytesChecked([]byte("x")); err == nil {
		t.Fatal("a backend whose rules failed scanned clean")
	}
	if m, err := b.ScanBytesChecked(nil); err != nil || m != nil {
		t.Fatalf("empty data = %v, %v", m, err)
	}
	if b.Stats().Spawns != 0 {
		t.Fatal("an empty scan started a worker")
	}
	_ = b.Stop()
	if _, err := b.ScanBytesChecked(nil); err == nil {
		t.Fatal("a stopped backend scanned empty data clean")
	}
}

// The disabled list applies to every compile, including the one that
// recovers from broken rules.
func TestReloadHonorsDisabledRulesAfterRecovery(t *testing.T) {
	fx := &backendFixture{
		dir:      rulesDir(t, map[string]string{"rules.yar": "syntax error"}),
		disabled: []string{"drop_me"},
	}
	b := newBackend(t, fx)
	if err := b.Reload(); err == nil {
		t.Fatal("bad rules compiled")
	}
	writeRule(t, fx.dir, "rules.yar", "marker:other\nrule drop_me {\nmarker:evil\n}\n")
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := ruleNames(t, b, "evil"); len(got) != 0 {
		t.Fatalf("a disabled rule matched after recovery: %v", got)
	}
}

func TestScanBytesSendsSealedDescriptor(t *testing.T) {
	fx := &backendFixture{scan: newHelper("report-sealed")}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := ruleNames(t, b, "an evil payload"); len(got) != 1 {
		t.Fatalf("scan through a sealed descriptor = %v", got)
	}
}

// Byte scans travel as a descriptor, so the frame cap does not limit them.
func TestScanBytesHasNoFrameCeiling(t *testing.T) {
	b := newBackend(t, &backendFixture{})
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	data := append(make([]byte, yaraipc.MaxFrameBytes+1), []byte("evil")...)
	if got := ruleNames(t, b, string(data)); len(got) != 1 {
		t.Fatalf("a scan past the frame cap = %v", got)
	}
}

// More rule files than one compile accepts is a property of the rule set:
// it is refused before any worker starts and is never reported as a worker
// outage to retry.
func TestReloadRefusesTooManyRuleFiles(t *testing.T) {
	files := make(map[string]string, yaraipc.MaxSources+1)
	for i := 0; i <= yaraipc.MaxSources; i++ {
		files[fmt.Sprintf("r%04d.yar", i)] = "marker:evil\n"
	}
	fx := &backendFixture{dir: rulesDir(t, files)}
	b := newBackend(t, fx)
	err := b.Reload()
	if err == nil || workerproc.FailureReason(err) != "" || !strings.Contains(err.Error(), "signatures.yara_worker_enabled") {
		t.Fatalf("reload error = %v (reason %q), want a rule-set error naming the knob", err, workerproc.FailureReason(err))
	}
	if fx.compile.launches.Load() != 0 {
		t.Fatal("a rule set over the file limit started a compile worker")
	}
}

// oomProcess is a compile worker the kernel killed for memory: its socket
// is already closed and it reports an OOM kill.
type oomProcess struct {
	conn *net.UnixConn
	done chan struct{}
}

func newOOMProcess(t *testing.T) *oomProcess {
	t.Helper()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = syscall.Close(pair[1])
	f := os.NewFile(uintptr(pair[0]), "oom-worker")
	c, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	close(done)
	return &oomProcess{conn: c.(*net.UnixConn), done: done}
}

func (p *oomProcess) Conn() *net.UnixConn   { return p.conn }
func (p *oomProcess) Kill() error           { return p.conn.Close() }
func (p *oomProcess) Done() <-chan struct{} { return p.done }
func (*oomProcess) PID() int                { return 1 }
func (*oomProcess) Retire() bool            { return false }
func (*oomProcess) OOMKilled() bool         { return true }

// A compile killed for memory under the compile worker's fixed cap failed
// because of the rule set: the error says so, names the way out, and is not
// classified as a worker outage to retry.
func TestCompileOutOfMemoryIsARuleSetError(t *testing.T) {
	fx := &backendFixture{compileFn: func(context.Context) (workerproc.Process, error) { return newOOMProcess(t), nil }}
	b := newBackend(t, fx)
	err := b.Reload()
	if err == nil || workerproc.FailureReason(err) != "" || !strings.Contains(err.Error(), "signatures.yara_worker_enabled") {
		t.Fatalf("reload error = %v (reason %q), want a rule-set error naming the knob", err, workerproc.FailureReason(err))
	}
	if b.CompileError() == "" {
		t.Fatal("an out-of-memory first compile left no compile error")
	}
}

// A compile worker that dies stays a worker failure, and the error names why.
func TestCompileCrashNamesReason(t *testing.T) {
	fx := &backendFixture{compile: newHelper("compile-crash")}
	b := newBackend(t, fx)
	err := b.Reload()
	if workerproc.FailureReason(err) != workerproc.ReasonCrash || !strings.Contains(err.Error(), "(crash)") {
		t.Fatalf("reload error = %v (reason %q), want a crash naming itself", err, workerproc.FailureReason(err))
	}
}
