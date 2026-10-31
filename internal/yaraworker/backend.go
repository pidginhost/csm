package yaraworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/workerproc"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// BackendConfig describes the daemon side of out-of-process YARA.
type BackendConfig struct {
	// ScanLaunch starts the scan worker and CompileLaunch a compile worker.
	// The daemon passes locked-down unit launchers.
	ScanLaunch, CompileLaunch workerproc.Launcher
	RulesDir                  string
	DisabledRules             []string
	// ScanTimeout bounds one scan, LoadTimeout a fresh worker loading the
	// compiled rules, CompileTimeout one compile.
	ScanTimeout, LoadTimeout, CompileTimeout time.Duration
	// OnFailure is told of every counted scan worker failure, and OnJob of
	// every scan worker request outcome. Both run under the worker
	// supervisor's lock and must not block.
	OnFailure func(reason string, err error)
	OnJob     func(outcome string, memory uint64)
	Log       func(string, ...any)
	// WarmAfterReload starts a scan worker in the background after every
	// successful reload, so the rules load off the scan path.
	WarmAfterReload bool
}

// Backend is the YARA backend the daemon installs with yara.SetActive. It
// reads rule text, has a short-lived compile worker compile it, keeps the
// compiled rules in a sealed memfd, and loads them into each scan worker it
// starts: a worker restart reloads, it never recompiles. Every scan reaches
// the worker as a descriptor, and a scan that did not run is an error.
type Backend struct {
	cfg  BackendConfig
	proc *workerproc.Supervisor
	ctx  context.Context
	stop context.CancelFunc

	// compileGate runs one compile at a time: each can need a gigabyte.
	// Waiting reloads must be able to cancel without stopping its owner.
	compileGate *semaphore.Weighted

	mu         sync.Mutex
	rules      *compiledRules
	compileErr string
	stopped    bool
	// gen numbers rule sets. A worker loaded with an older one retires.
	gen atomic.Uint64

	scanErrs scanErrLog
}

// compiledRules is one compiled rule set, held by the daemon.
type compiledRules struct {
	file  *os.File
	count int
	gen   uint64
}

// NewBackend validates cfg. It compiles nothing and starts no worker.
func NewBackend(cfg BackendConfig) (*Backend, error) {
	if cfg.ScanLaunch == nil || cfg.CompileLaunch == nil {
		return nil, errors.New("yaraworker: scan and compile launchers are required")
	}
	if cfg.ScanTimeout <= 0 || cfg.LoadTimeout <= 0 || cfg.CompileTimeout <= 0 {
		return nil, errors.New("yaraworker: timeouts must be positive")
	}
	b := &Backend{cfg: cfg, compileGate: semaphore.NewWeighted(1)}
	proc, err := workerproc.New(workerproc.Config{
		Name:    "yara worker",
		Launch:  b.launch,
		Timeout: cfg.ScanTimeout,
		// MaxFDs 0: a scan reply carrying a descriptor is a protocol failure.
		Limits:    workerproc.Limits{MaxFrameBytes: yaraipc.MaxFrameBytes},
		Log:       cfg.Log,
		OnFailure: cfg.OnFailure,
		OnJob:     cfg.OnJob,
		// A file that kills the worker must not switch YARA off for every
		// other file on the host: only a failed start counts toward the
		// breaker, so hostile content costs one restart per scan.
		BreakOnSpawnOnly: true,
	})
	if err != nil {
		return nil, err
	}
	b.proc = proc
	b.ctx, b.stop = context.WithCancel(context.Background())
	return b, nil
}

// Reload compiles the rules directory in a compile worker and, on success,
// makes the result the rules every later scan uses. On failure the current
// rules stay; with none loaded the failure becomes CompileError and scans
// fail closed. An error that workerproc.FailureReason classifies came from
// the compile worker, not the rules.
func (b *Backend) Reload() error {
	return b.ReloadContext(context.Background())
}

// ReloadContext lets startup retries cancel a compile as soon as shutdown
// begins, before the daemon finishes draining its other workers.
func (b *Backend) ReloadContext(ctx context.Context) error {
	if err := b.compileGate.Acquire(ctx, 1); err != nil {
		return err
	}
	defer b.compileGate.Release(1)
	if b.isStopped() {
		return workerproc.ErrStopped
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sources, disabled, err := yara.ReadSources(b.cfg.RulesDir, b.cfg.DisabledRules)
	if err != nil {
		return b.failReload(err)
	}
	if len(sources) == 0 {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.stopped {
			return workerproc.ErrStopped
		}
		if b.rules != nil {
			return fmt.Errorf("no YARA rule files found in %s", b.cfg.RulesDir)
		}
		b.compileErr = ""
		return nil
	}
	f, count, err := b.compile(ctx, sources)
	if err == nil && count == 0 && disabled == 0 {
		_ = f.Close()
		err = fmt.Errorf("no YARA rules compiled from %s", b.cfg.RulesDir)
	}
	if err != nil {
		return b.failReload(err)
	}

	b.mu.Lock()
	if b.stopped || ctx.Err() != nil {
		b.mu.Unlock()
		_ = f.Close()
		if err := ctx.Err(); err != nil {
			return err
		}
		return workerproc.ErrStopped
	}
	old := b.rules
	b.rules = &compiledRules{file: f, count: count, gen: b.gen.Add(1)}
	b.compileErr = ""
	b.mu.Unlock()
	if old != nil {
		_ = old.file.Close()
	}
	yara.InvalidateCaches()
	if b.cfg.WarmAfterReload && count > 0 {
		// A failed warm-up is reported through OnFailure like any request.
		obs.Go("yara-worker-warm", func() { _ = b.Warm() })
	}
	return nil
}

func (b *Backend) failReload(err error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return workerproc.ErrStopped
	}
	if b.rules == nil {
		b.compileErr = err.Error()
	}
	return err
}

// TestCompile compiles source alone, without touching the scanning rules,
// so a downloaded rule file can be checked before it is installed.
func (b *Backend) TestCompile(source string) error {
	if err := b.compileGate.Acquire(b.ctx, 1); err != nil {
		return workerproc.ErrStopped
	}
	defer b.compileGate.Release(1)
	if b.isStopped() {
		return workerproc.ErrStopped
	}
	f, count, err := b.compile(context.Background(), []yara.Source{{Name: "source", Text: []byte(source)}})
	if err != nil {
		return err
	}
	_ = f.Close()
	if count == 0 {
		return errors.New("no rules compiled from source")
	}
	return nil
}

// compile runs one compile worker over sources and returns the compiled
// rules copied into a memfd this process owns and sealed.
func (b *Backend) compile(ctx context.Context, sources []yara.Source) (*os.File, int, error) {
	if b.isStopped() {
		return nil, 0, workerproc.ErrStopped
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(b.ctx, cancel)
	defer func() { stop(); cancel() }()
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	var args yaraipc.CompileArgs
	var text bytes.Buffer
	for _, src := range sources {
		args.Sources = append(args.Sources, yaraipc.SourceSpan{Name: src.Name, Size: int64(len(src.Text))})
		text.Write(src.Text)
	}
	input, err := yaraipc.SealedMemfd("csm-yara-sources", text.Bytes())
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = input.Close() }()
	payload, err := json.Marshal(args)
	if err != nil {
		return nil, 0, err
	}
	sup, err := workerproc.New(workerproc.Config{
		Name:    "yara compile worker",
		Launch:  b.cfg.CompileLaunch,
		Timeout: b.cfg.CompileTimeout,
		Limits:  workerproc.Limits{MaxFrameBytes: yaraipc.MaxFrameBytes, MaxFDs: 1},
		Log:     b.cfg.Log,
	})
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = sup.Stop() }()

	var res struct {
		RuleCount    *int   `json:"rule_count"`
		CompileError string `json:"compile_error,omitempty"`
	}
	var size int64
	_, fds, err := sup.Call(ctx, workerproc.Frame{Op: yaraipc.OpCompile, Payload: payload}, []*os.File{input},
		func(reply workerproc.Frame, fds []*os.File) (bool, error) {
			if decodeErr := decodeArgs(reply.Payload, &res); decodeErr != nil {
				return false, fmt.Errorf("compile reply: %w", decodeErr)
			}
			if res.RuleCount == nil || *res.RuleCount < 0 {
				return false, errors.New("compile reply: missing or invalid rule count")
			}
			if res.CompileError != "" {
				if len(fds) != 0 || *res.RuleCount != 0 {
					return false, errors.New("compile reply: a failed compile returned rules")
				}
				return false, nil
			}
			if len(fds) != 1 {
				return false, fmt.Errorf("compile reply: %d descriptors, want 1", len(fds))
			}
			st, statErr := fds[0].Stat()
			if statErr != nil {
				return false, fmt.Errorf("compile reply: %w", statErr)
			}
			if !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > yaraipc.MaxSerializedRules {
				return false, fmt.Errorf("compile reply: compiled rules of %d bytes, want 1 to %d", st.Size(), yaraipc.MaxSerializedRules)
			}
			size = st.Size()
			return false, nil
		})
	if err != nil {
		return nil, 0, err
	}
	if res.CompileError != "" {
		return nil, 0, errors.New(res.CompileError)
	}
	defer func() { _ = fds[0].Close() }()
	kept, err := yaraipc.CopySealedMemfd("csm-yara-rules", fds[0], size)
	if err != nil {
		return nil, 0, err
	}
	return kept, *res.RuleCount, nil
}

// launch starts a scan worker and loads the current rules into it before the
// supervisor may send it a scan.
func (b *Backend) launch(ctx context.Context) (workerproc.Process, error) {
	b.mu.Lock()
	rules := b.rules
	var ro *os.File
	var err error
	if rules != nil {
		// Under the lock: a reload closes the file it replaces.
		ro, err = yaraipc.ReopenReadOnly(rules.file)
	}
	b.mu.Unlock()
	if rules == nil {
		return nil, errors.New("no compiled YARA rules")
	}
	if err != nil {
		return nil, fmt.Errorf("compiled YARA rules: %w", err)
	}
	defer func() { _ = ro.Close() }()

	p, err := b.cfg.ScanLaunch(ctx)
	if err != nil {
		return nil, err
	}
	if err := b.loadRules(ctx, p, ro, rules.count); err != nil {
		// Asked before the kill: the unit's cgroup holds the evidence.
		if r, ok := p.(interface{ OOMKilled() bool }); ok && r.OOMKilled() {
			err = fmt.Errorf("%w (out of memory)", err)
		}
		_ = p.Kill()
		_ = p.Conn().Close()
		return nil, err
	}
	return &rulesProcess{Process: p, gen: rules.gen, current: &b.gen}, nil
}

func (b *Backend) loadRules(ctx context.Context, p workerproc.Process, rules *os.File, count int) error {
	conn := p.Conn()
	deadline := time.Now().Add(b.cfg.LoadTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	if err := workerproc.SendFrame(conn, workerproc.Frame{Op: yaraipc.OpLoad}, []*os.File{rules}, yaraipc.MaxFrameBytes); err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	// MaxFDs 0: ReceiveFrame closes and refuses any descriptor.
	reply, _, err := workerproc.ReceiveFrame(conn, workerproc.Limits{MaxFrameBytes: yaraipc.MaxFrameBytes})
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	if reply.Error != "" || reply.Op != "" {
		return fmt.Errorf("load rules: worker refused: %q", reply.Error)
	}
	loaded, err := decodeRuleCount(reply.Payload)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	if loaded != count {
		return fmt.Errorf("load rules: worker loaded %d rules, want %d", loaded, count)
	}
	return nil
}

func decodeRuleCount(payload json.RawMessage) (int, error) {
	var res struct {
		RuleCount *int `json:"rule_count"`
	}
	if err := decodeArgs(payload, &res); err != nil {
		return 0, err
	}
	if res.RuleCount == nil || *res.RuleCount < 0 {
		return 0, errors.New("missing or invalid rule count")
	}
	return *res.RuleCount, nil
}

// rulesProcess is a scan worker that retires once newer rules exist. It
// passes on the optional memory interfaces workerproc looks for, which
// embedding the Process interface alone would hide.
type rulesProcess struct {
	workerproc.Process
	gen     uint64
	current *atomic.Uint64
}

func (p *rulesProcess) Retire() bool {
	return p.gen != p.current.Load() || p.Process.Retire()
}

func (p *rulesProcess) MemoryUsed() uint64 {
	if r, ok := p.Process.(interface{ MemoryUsed() uint64 }); ok {
		return r.MemoryUsed()
	}
	return 0
}

func (p *rulesProcess) OOMKilled() bool {
	if r, ok := p.Process.(interface{ OOMKilled() bool }); ok {
		return r.OOMKilled()
	}
	return false
}

// ScanBytes flattens a failed scan to no matches; callers that must fail
// closed use ScanBytesChecked.
func (b *Backend) ScanBytes(data []byte) []yara.Match {
	m, _ := b.ScanBytesChecked(data)
	return m
}

// ScanBytesChecked scans bytes the daemon holds; they reach the worker as a
// sealed memfd. With no rules, or a set whose every rule is disabled, it
// answers clean without a worker, as the in-process scanner does, unless the
// rules failed to compile.
func (b *Backend) ScanBytesChecked(data []byte) ([]yara.Match, error) {
	rules, compileErr, stopped := b.state()
	if stopped {
		return nil, workerproc.ErrStopped
	}
	if len(data) == 0 {
		return nil, nil
	}
	if rules == nil || rules.count == 0 {
		if compileErr == "" {
			return nil, nil
		}
		return nil, fmt.Errorf("yara scanner unavailable: %s", compileErr)
	}
	f, err := yaraipc.SealedMemfd("csm-yara-scan", data)
	if err != nil {
		b.logScanErr(err)
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return b.scan(f, len(data))
}

// ScanFDChecked scans the first size bytes of f, such as a mail part. The
// worker gets its own read-only open. It requires at least one compiled rule.
func (b *Backend) ScanFDChecked(f *os.File, size int64) ([]yara.Match, error) {
	if size <= 0 || size > int64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("yaraworker: invalid descriptor scan size: %d", size)
	}
	rules, compileErr, stopped := b.state()
	if stopped {
		return nil, workerproc.ErrStopped
	}
	if rules == nil || rules.count == 0 {
		if compileErr == "" {
			compileErr = "no compiled rules"
		}
		return nil, fmt.Errorf("yara scanner unavailable: %s", compileErr)
	}
	ro, err := yaraipc.ReopenReadOnly(f)
	if err != nil {
		err = fmt.Errorf("yaraworker: reopen read-only: %w", err)
		b.logScanErr(err)
		return nil, err
	}
	defer func() { _ = ro.Close() }()
	return b.scan(ro, int(size))
}

func (b *Backend) scan(f *os.File, size int) ([]yara.Match, error) {
	payload, err := json.Marshal(yaraipc.ScanFDArgs{MaxBytes: size})
	if err != nil {
		return nil, err
	}
	var matches []yaraipc.Match
	_, _, err = b.proc.Call(context.Background(), workerproc.Frame{Op: yaraipc.OpScanFD, Payload: payload}, []*os.File{f},
		func(reply workerproc.Frame, _ []*os.File) (bool, error) {
			m, decodeErr := yaraipc.DecodeScanReply(reply.Payload)
			matches = m
			return false, decodeErr
		})
	if err != nil {
		b.logScanErr(err)
		return nil, err
	}
	return toYaraMatches(matches), nil
}

// Warm starts the scan worker and loads the rules now, so the first scan
// after a compile does not wait for the load. Without rules it does nothing.
func (b *Backend) Warm() error {
	if rules, _, _ := b.state(); rules == nil || rules.count == 0 {
		return nil
	}
	_, _, err := b.proc.Call(context.Background(), workerproc.Frame{Op: yaraipc.OpPing}, nil,
		func(reply workerproc.Frame, _ []*os.File) (bool, error) {
			_, decodeErr := decodeRuleCount(reply.Payload)
			return false, decodeErr
		})
	return err
}

// RuleCount is the number of compiled rules scans use.
func (b *Backend) RuleCount() int {
	if rules, _, _ := b.state(); rules != nil {
		return rules.count
	}
	return 0
}

// CompileError is why no rules are loaded, or "" when rules are loaded or
// the rule set is empty.
func (b *Backend) CompileError() string {
	_, compileErr, _ := b.state()
	return compileErr
}

// Stop cancels compilation, kills the scan worker, and refuses later work.
func (b *Backend) Stop() error {
	b.mu.Lock()
	b.stopped = true
	b.stop()
	b.mu.Unlock()
	err := b.proc.Stop()
	// A compile owns its short-lived supervisor until it returns. Wait for
	// its canceled call to kill and reap that worker before finishing stop.
	_ = b.compileGate.Acquire(context.Background(), 1)
	defer b.compileGate.Release(1)
	b.mu.Lock()
	rules := b.rules
	b.rules = nil
	b.mu.Unlock()
	if rules != nil {
		_ = rules.file.Close()
	}
	return err
}

// Stats is the scan worker supervisor's state.
func (b *Backend) Stats() workerproc.Stats { return b.proc.Stats() }

// QueueStatuses reports the scan worker's request queue.
func (b *Backend) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return b.proc.QueueStatuses(now)
}

// Snapshot shutdown and rules together: Stop clears the rules, which must
// not be mistaken for the empty-directory exception in a byte scan.
func (b *Backend) state() (*compiledRules, string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rules, b.compileErr, b.stopped
}

func (b *Backend) current() *compiledRules {
	rules, _, _ := b.state()
	return rules
}

func (b *Backend) isStopped() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stopped
}

func (b *Backend) logScanErr(err error) { b.scanErrs.log(b.logf, err) }

func (b *Backend) logf(format string, args ...any) {
	if b.cfg.Log != nil {
		b.cfg.Log(format, args...)
	}
}

func toYaraMatches(in []yaraipc.Match) []yara.Match {
	if len(in) == 0 {
		return nil
	}
	out := make([]yara.Match, len(in))
	for i := range in {
		out[i] = yara.Match{RuleName: in[i].RuleName, Meta: in[i].Meta}
	}
	return out
}
