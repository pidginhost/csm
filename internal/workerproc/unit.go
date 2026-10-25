package workerproc

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/pidginhost/csm/internal/systemdrun"
)

// UnitConfig describes workers run as locked-down transient systemd units.
type UnitConfig struct {
	// Prefix names the units: Prefix + "-" + a generation number. Each
	// supervisor needs a distinct prefix because it owns the slice's count.
	Prefix  string
	Command string
	Args    []string
	// MemoryLimit caps memory and swap together, in bytes.
	MemoryLimit uint64
	// FileSizeLimit is LimitFSIZE. It bounds the worker's memfds too, so it
	// must exceed the largest reply a worker writes.
	FileSizeLimit uint64
	RuntimeMax    time.Duration
	// StartTimeout bounds unit start, hello and the memory cap together.
	StartTimeout time.Duration
	Protocol     int
	// Limits applies to the hello reply.
	Limits Limits
	Log    func(string, ...any)
	// InaccessiblePaths are hidden from the worker on top of ProtectHome:
	// account homes on other volumes. Paths that are not absolute and clean,
	// or that hold spaces, quotes, backslashes, percent signs or control
	// bytes, are dropped.
	InaccessiblePaths []string

	hooks *unitHooks // tests only; nil means the real system
}

// unitHooks are the system calls the launcher makes, replaced in tests.
type unitHooks struct {
	systemdRun           string
	configureSlice       func(ctx context.Context, name string) error
	mainPID              func(ctx context.Context, p *unitProcess) (int, error)
	killUnit             func(ctx context.Context, p *unitProcess) error
	procRoot, cgroupRoot string
	pollInterval         time.Duration
}

// unitKillTimeout bounds one systemctl kill.
const unitKillTimeout = 5 * time.Second

// oomWatchGrace bounds how long a dead worker's OOM watch may still report.
const oomWatchGrace = time.Second

// unitGeneration numbers units. Seeded with the start time so a restarted
// daemon does not reuse the name of a unit still being torn down.
var unitGeneration = func() *atomic.Int64 {
	var g atomic.Int64
	g.Store(time.Now().UnixNano())
	return &g
}()

// lockdownProperties are the unit properties every worker runs under: no
// network, no host files, no privileges, bounded memory, tasks and files.
func lockdownProperties(cfg UnitConfig) []string {
	memory := strconv.FormatUint(cfg.MemoryLimit, 10)
	props := []string{
		"DynamicUser=yes",
		"CapabilityBoundingSet=",
		"NoNewPrivileges=yes",
		"PrivateNetwork=yes",
		"RestrictAddressFamilies=AF_UNIX",
		"ProtectSystem=strict",
		"ProtectHome=yes",
		"PrivateTmp=yes",
		"PrivateDevices=yes",
		"ProtectKernelTunables=yes",
		"ProtectKernelModules=yes",
		"ProtectControlGroups=yes",
		"RestrictNamespaces=yes",
		"RestrictRealtime=yes",
		"MemoryDenyWriteExecute=yes",
		"UMask=0077",
		"SystemCallFilter=@system-service",
		// In place of LockPersonality=yes, which systemd-run on systemd 239
		// rejects as an unknown assignment. Denying personality(2) outright
		// is stricter, and no worker needs it.
		"SystemCallFilter=~personality",
		"SystemCallErrorNumber=EPERM",
		"MemoryAccounting=yes",
		"MemoryLimit=" + memory,
		"MemoryMax=" + memory,
		"MemorySwapMax=0",
		"TasksMax=64",
		"LimitNOFILE=256",
		"LimitCORE=0",
		"LimitFSIZE=" + strconv.FormatUint(cfg.FileSizeLimit, 10),
		// The containing slice gets the same weight before launch.
		"CPUWeight=50",
		// Prefer a hostile parser as the victim under host memory pressure.
		"OOMScoreAdjust=1000",
		"Slice=" + unitSlice(cfg.Prefix),
	}
	paths, _ := inaccessiblePaths(cfg.InaccessiblePaths)
	for _, p := range paths {
		// "-": a path missing on this host is not an error.
		props = append(props, "InaccessiblePaths=-"+p)
	}
	return props
}

// inaccessiblePaths returns the usable paths sorted and without duplicates,
// and the ones it dropped.
func inaccessiblePaths(in []string) (keep, dropped []string) {
	seen := make(map[string]bool, len(in))
	for _, p := range in {
		if p == "/" || !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, " \t\n\"'\\%") || strings.ContainsFunc(p, unicode.IsControl) {
			dropped = append(dropped, p)
			continue
		}
		if !seen[p] {
			seen[p] = true
			keep = append(keep, p)
		}
	}
	sort.Strings(keep)
	return keep, dropped
}

// unitSlice is the slice a prefix's units run in: one per prefix, directly
// under system.slice, so workers share system.slice's resources. On cgroup
// v2, work is admitted only once earlier units are gone; memory.events then
// counts the current unit's OOM kills and outlives its own cgroup.
func unitSlice(prefix string) string {
	return "system-" + strings.ReplaceAll(prefix, "-", `\x2d`) + ".slice"
}

// UnitLauncher starts each worker as its own transient unit through
// `systemd-run --pipe`, whose stdin and stdout are the worker's socket. A
// worker is handed out only after hello and verification of its own memory
// cgroup's cap and usage; there is no fallback to direct execution.
func UnitLauncher(cfg UnitConfig) Launcher {
	h := unitHooks{}
	if cfg.hooks != nil {
		h = *cfg.hooks
	}
	if h.mainPID == nil {
		h.mainPID = systemctlMainPID
	}
	if h.configureSlice == nil {
		h.configureSlice = systemctlConfigureSlice
	}
	if h.killUnit == nil {
		h.killUnit = systemctlKill
	}
	if h.procRoot == "" {
		h.procRoot = "/proc"
	}
	if h.cgroupRoot == "" {
		h.cgroupRoot = "/sys/fs/cgroup"
	}
	if h.pollInterval <= 0 {
		h.pollInterval = 500 * time.Millisecond
	}
	if _, dropped := inaccessiblePaths(cfg.InaccessiblePaths); len(dropped) > 0 && cfg.Log != nil {
		cfg.Log("%s: not hiding unusable paths %q", cfg.Prefix, dropped)
	}
	return func(ctx context.Context) (Process, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p, err := startUnit(ctx, cfg, &h)
		if err != nil {
			return nil, fmt.Errorf("workerproc: isolation unavailable: %w", err)
		}
		return p, nil
	}
}

func startUnit(ctx context.Context, cfg UnitConfig, h *unitHooks) (*unitProcess, error) {
	startCtx, cancel := context.WithTimeout(ctx, cfg.StartTimeout)
	defer cancel()
	path := h.systemdRun
	if path == "" {
		var err error
		if path, err = exec.LookPath("systemd-run"); err != nil {
			return nil, err
		}
	}
	// CPU weights compare siblings. A weight on the only service in a
	// default-weight slice would let it outweigh csm.service instead.
	if err := h.configureSlice(startCtx, unitSlice(cfg.Prefix)); err != nil {
		return nil, fmt.Errorf("configure worker slice: %w", err)
	}
	conn, childFile, err := workerSocket()
	if err != nil {
		return nil, err
	}

	unit := cfg.Prefix + "-" + strconv.FormatInt(unitGeneration.Add(1), 10)
	name, args := systemdrun.Argv(path, systemdrun.Options{
		Pipe:       true,
		RuntimeMax: cfg.RuntimeMax,
		Unit:       unit,
		Properties: lockdownProperties(cfg),
	}, cfg.Command, cfg.Args...)
	// Not CommandContext: ending the request must not kill the worker.
	cmd := exec.Command(name, args...) // #nosec G204 -- systemd-run with fixed flags and the daemon's own binary.
	// The worker's output is untrusted: it reaches the log quoted and capped.
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		_ = childFile.Close()
		_ = conn.Close()
		return nil, err
	}
	cmd.Stdin = childFile
	cmd.Stdout = childFile
	cmd.Stderr = stderrW
	err = cmd.Start()
	// Closed at once, not deferred: while the daemon holds the child's end,
	// a systemd-run that exits early leaves the hello waiting for its
	// deadline instead of reading end of file.
	_ = childFile.Close()
	_ = stderrW.Close()
	if err != nil {
		_ = stderrR.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("start systemd-run: %w", err)
	}
	logf := cfg.Log
	if logf == nil {
		logf = func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
	}
	go func() {
		defer func() { _ = stderrR.Close() }()
		logWorkerOutput(stderrR, unit, logf)
	}()
	p := &unitProcess{unit: unit, cmd: cmd, conn: conn, done: make(chan struct{}), killUnit: h.killUnit, log: cfg.Log}
	go func() {
		_ = cmd.Wait()
		// The unit belongs to PID 1 and can outlive the systemd-run client.
		_ = p.Kill()
		close(p.done)
	}()

	if err := p.start(startCtx, cfg, h); err != nil {
		_ = p.Kill()
		_ = conn.Close()
		select {
		case <-p.done:
		case <-time.After(reapTimeout):
			p.logf("unit %s did not stop", unit)
		}
		return nil, fmt.Errorf("unit %s: %w", unit, err)
	}
	return p, nil
}

// start finishes a launch: hello, then the main PID, which only systemd
// reports, never the worker.
func (p *unitProcess) start(ctx context.Context, cfg UnitConfig, h *unitHooks) error {
	stop := context.AfterFunc(ctx, func() { _ = p.conn.Close() })
	defer stop()
	if err := Handshake(ctx, p.conn, cfg.Limits, cfg.Protocol); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	pid, err := h.mainPID(ctx, p)
	if err != nil {
		return fmt.Errorf("main PID: %w", err)
	}
	if pid <= 0 {
		return errors.New("unit has no main process")
	}
	p.pid = pid

	cg, found, err := findMemoryCgroup(h.procRoot, h.cgroupRoot, pid, p.unit)
	if err != nil {
		return fmt.Errorf("cannot cap worker memory: %w", err)
	}
	if !found {
		// Polling the main process alone would miss any child it forks.
		return errors.New("cannot cap worker memory: no memory cgroup for the unit")
	}
	if capErr := cg.checkRAMLimit(cfg.MemoryLimit); capErr != nil {
		return fmt.Errorf("cannot cap worker memory: %w", capErr)
	}
	if capErr := cg.capSwap(cfg.MemoryLimit, h.procRoot); capErr != nil {
		return fmt.Errorf("cannot cap worker memory: %w", capErr)
	}
	p.cg = cg
	if cg.v2 {
		// The unit's own counters vanish with its cgroup before the daemon
		// sees the worker die; the slice's hierarchical ones stay.
		if dir := filepath.Dir(cg.dir); filepath.Base(dir) == unitSlice(cfg.Prefix) {
			// Reaping systemd-run is not proof that its service is gone:
			// killing the unit is asynchronous and can fail or time out.
			if waitErr := waitForUnitSlice(ctx, dir, filepath.Base(cg.dir), h.pollInterval); waitErr != nil {
				return fmt.Errorf("wait for worker slice: %w", waitErr)
			}
			slice := memoryCgroup{dir: dir, v2: true}
			if n, serr := slice.oomKills(); serr == nil {
				p.slice, p.sliceOOMKills = &slice, n
			}
		}
		if p.slice == nil {
			p.logf("unit %s: memory kills will read as crashes: no slice counter", p.unit)
		}
	} else if w, werr := cg.watchOOM(); werr != nil {
		p.logf("unit %s: memory kills will read as crashes: %v", p.unit, werr)
	} else {
		p.oom = w
		go func() {
			// The watch ends with the cgroup; this bounds it if the kernel
			// never reports the removal.
			<-p.done
			time.Sleep(oomWatchGrace)
			w.stop()
		}()
	}
	p.usage = func() (uint64, error) { return cg.usage(h.procRoot) }
	used, err := p.usage()
	if err != nil {
		return fmt.Errorf("cannot measure worker memory: %w", err)
	}
	if used > cfg.MemoryLimit {
		return fmt.Errorf("worker memory %d over cap %d", used, cfg.MemoryLimit)
	}
	// Stop the startup cancellation hook before handing out the socket.
	// If cancellation won, the callback may still be closing it.
	stop()
	if err := ctx.Err(); err != nil {
		return err
	}
	p.limit = cfg.MemoryLimit
	if cfg.RuntimeMax > 0 {
		p.retireAt = time.Now().Add(cfg.RuntimeMax - cfg.RuntimeMax/4)
	}
	go p.watch(h.pollInterval)
	return nil
}

func waitForUnitSlice(ctx context.Context, dir, unit string, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		found, shared := false, false
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			if entry.Name() == unit {
				found = true
			} else {
				shared = true
			}
		}
		if !found {
			return errors.New("worker cgroup disappeared")
		}
		if !shared {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// watch kills the worker once its memory and swap pass the cap, in case the
// kernel's own limit did not take effect. It fails closed: usage that cannot
// be read while the worker is alive kills it too.
func (p *unitProcess) watch(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
		}
		used, err := p.usage()
		if err == nil && used <= p.limit {
			continue
		}
		if err != nil && localExhaustion(err) {
			// The daemon is out of descriptors, not the worker out of
			// line; the kernel cap was verified at start.
			continue
		}
		select {
		case <-p.done:
			return // Gone already: its counters vanished with it.
		default:
		}
		if err != nil {
			p.logf("unit %s: cannot read memory, killing: %v", p.unit, err)
		} else {
			p.logf("unit %s: memory %d over cap %d, killing", p.unit, used, p.limit)
			p.memoryKill.Store(true)
		}
		_ = p.Kill()
		return
	}
}

// unitProcess is one worker unit. Done follows the systemd-run client, which
// exits when the unit ends.
type unitProcess struct {
	unit     string
	cmd      *exec.Cmd
	conn     *net.UnixConn
	done     chan struct{}
	pid      int
	killUnit func(ctx context.Context, p *unitProcess) error
	kill     sync.Once
	log      func(string, ...any)
	// usage reads memory and swap in use; limit is the cap it is held to.
	// lastUsed is what Retire last read.
	usage    func() (uint64, error)
	limit    uint64
	lastUsed atomic.Uint64
	// retireAt is three quarters into RuntimeMaxSec; zero means no cap.
	retireAt time.Time
	// cg is the unit's memory cgroup; memoryKill records the watchdog
	// killing the worker for memory.
	cg         memoryCgroup
	memoryKill atomic.Bool
	// oom follows the kernel's OOM kills in cg on cgroup v1; slice and
	// sliceOOMKills, the count at start, read them on v2. Without either a
	// memory kill reads as a crash.
	oom           *oomWatch
	slice         *memoryCgroup
	sliceOOMKills uint64
}

func (p *unitProcess) Conn() *net.UnixConn   { return p.conn }
func (p *unitProcess) Done() <-chan struct{} { return p.done }
func (p *unitProcess) PID() int              { return p.pid }

// Retire asks for a fresh worker once this one holds more than three
// quarters of its cap after a job, or its usage cannot be read, or it is
// three quarters into its lifetime cap: systemd ending it mid-request would
// charge that request's input with a worker failure.
func (p *unitProcess) Retire() bool {
	if !p.retireAt.IsZero() && time.Now().After(p.retireAt) {
		return true
	}
	if p.usage == nil {
		return false
	}
	used, err := p.usage()
	if err == nil {
		p.lastUsed.Store(used)
	}
	return err != nil || used > p.limit/4*3
}

// MemoryUsed is the memory and swap in use when Retire last read it, or 0.
func (p *unitProcess) MemoryUsed() uint64 { return p.lastUsed.Load() }

// Kill asks systemd to SIGKILL the unit and returns at once: the supervisor
// calls it holding its lock, and a hung systemctl must not freeze it. The
// worker is killed by unit name, never by a PID it could have influenced.
func (p *unitProcess) Kill() error {
	p.kill.Do(func() {
		// A failed watchdog check must prevent further requests even while
		// systemctl is stalled or fails to reach the manager.
		_ = p.conn.Close()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), unitKillTimeout)
			defer cancel()
			if err := p.killUnit(ctx, p); err != nil {
				p.logf("kill unit %s: %v", p.unit, err)
			}
		}()
	})
	return nil
}

// OOMKilled reports a memory kill: by the watchdog, or by the kernel as the
// v2 slice recorded it or the v1 OOM watch saw it. The unit's own counters
// are a fallback while its cgroup still exists. On v1 it waits briefly for
// the watch's verdict, since the removal notification may still be pending.
func (p *unitProcess) OOMKilled() bool {
	if p.memoryKill.Load() {
		return true
	}
	if p.slice != nil {
		if n, err := p.slice.oomKills(); err == nil && n > p.sliceOOMKills {
			return true
		}
	}
	if p.oom != nil && p.oom.wait(oomWatchGrace) {
		return true
	}
	n, err := p.cg.oomKills()
	return err == nil && n > 0
}

func (p *unitProcess) logf(format string, args ...any) {
	if p.log != nil {
		p.log(format, args...)
	}
}

func systemctlMainPID(ctx context.Context, p *unitProcess) (int, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "MainPID", "--value", p.unit+".service").Output() // #nosec G204 -- the unit name is ours.
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

func systemctlConfigureSlice(ctx context.Context, name string) error {
	out, err := exec.CommandContext(ctx, "systemctl", "set-property", "--runtime", name, "CPUWeight=50").CombinedOutput() // #nosec G204 -- the slice name comes from the caller's unit prefix.
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func systemctlKill(ctx context.Context, p *unitProcess) error {
	out, err := exec.CommandContext(ctx, "systemctl", "kill", "--signal=SIGKILL", p.unit+".service").CombinedOutput() // #nosec G204 -- the unit name is ours.
	if err != nil && !strings.Contains(string(out), "not loaded") {
		// "not loaded": the unit already ended, which is what Kill wants.
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CheckUnitCommand reports why a unit's dynamic user could not run path: the
// file must be executable by others, which needs no read permission for a
// compiled binary, and every directory above it searchable by others.
func CheckUnitCommand(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("workerproc: unit command %q is not an absolute path", path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o001 == 0 {
		return fmt.Errorf("workerproc: %s is mode %04o; worker units need it executable by others, such as 0711", path, st.Mode().Perm())
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		st, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if st.Mode().Perm()&0o001 == 0 {
			return fmt.Errorf("workerproc: %s is mode %04o; worker units need it searchable by others", dir, st.Mode().Perm())
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

// StopUnits SIGKILLs every unit whose name starts with prefix, for leftovers
// of a daemon that died without stopping its workers.
func StopUnits(ctx context.Context, prefix string) error {
	out, err := exec.CommandContext(ctx, "systemctl", "kill", "--signal=SIGKILL", "--", prefix+"*.service").CombinedOutput() // #nosec G204 -- the prefix is a constant of the caller.
	if err != nil {
		return fmt.Errorf("workerproc: stop units %s*: %w: %s", prefix, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Bounds on worker output in the daemon's log.
const (
	maxWorkerLogLine  = 512
	maxWorkerLogBytes = 64 << 10
)

// logWorkerOutput logs r line by line, quoted, each line cut to
// maxWorkerLogLine bytes, until maxWorkerLogBytes are logged; then it says so
// once and drains r to end of file.
func logWorkerOutput(r io.Reader, unit string, logf func(string, ...any)) {
	br := bufio.NewReader(r)
	budget := maxWorkerLogBytes
	for {
		line, err := readCappedLine(br, maxWorkerLogLine)
		if len(line) > 0 || err == nil {
			if len(line) > budget {
				logf("%s: further output dropped", unit)
				_, _ = io.Copy(io.Discard, br)
				return
			}
			budget -= len(line)
			logf("%s: %q", unit, line)
		}
		if err != nil {
			return
		}
	}
}

// readCappedLine reads one line and returns at most max bytes of it, without
// the newline. The rest of a longer line is read and discarded.
func readCappedLine(br *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		chunk = bytes.TrimSuffix(chunk, []byte("\n"))
		if room := max - len(line); room > 0 {
			line = append(line, chunk[:min(room, len(chunk))]...)
		}
		if err != bufio.ErrBufferFull {
			return line, err
		}
	}
}
