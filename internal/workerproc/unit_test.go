package workerproc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// unitFake records what the fake systemd hooks were asked to do.
type unitFake struct {
	mu     sync.Mutex
	killed []*unitProcess
	// layout is the fake cgroup tree the "unit" lands in: v2, v1-memsw,
	// v1-noswap, v1-uncappable, or none.
	layout, prefix       string
	procRoot, cgroupRoot string
}

func (f *unitFake) kills() []*unitProcess {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*unitProcess(nil), f.killed...)
}

// waitKills waits for at least n killUnit calls; Kill runs them on their own
// goroutine.
func (f *unitFake) waitKills(t *testing.T, n int) []*unitProcess {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := f.kills(); len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("killUnit called %d times, want %d", len(f.kills()), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fakeUnitConfig runs this test binary as systemd-run; TestMain turns it into
// a worker serving fd 0. The "unit" is that process.
func fakeUnitConfig(t *testing.T, helperArgs ...string) (UnitConfig, *unitFake) {
	t.Helper()
	f := &unitFake{layout: "v2", prefix: "csm-parse-worker-zip0", procRoot: t.TempDir(), cgroupRoot: t.TempDir()}
	return UnitConfig{
		Prefix:        f.prefix,
		Command:       os.Args[0],
		Args:          append([]string{unitHelperArg}, helperArgs...),
		MemoryLimit:   512 << 20,
		FileSizeLimit: 64 << 20,
		RuntimeMax:    time.Hour,
		StartTimeout:  10 * time.Second,
		Protocol:      1,
		Limits:        Limits{MaxFrameBytes: 1 << 20, MaxFDs: 1},
		hooks: &unitHooks{
			systemdRun:     os.Args[0],
			configureSlice: func(context.Context, string) error { return nil },
			mainPID: func(_ context.Context, p *unitProcess) (int, error) {
				pid := p.cmd.Process.Pid
				return pid, f.writeCgroup(pid, p.unit)
			},
			killUnit: func(_ context.Context, p *unitProcess) error {
				f.mu.Lock()
				f.killed = append(f.killed, p)
				f.mu.Unlock()
				err := p.cmd.Process.Kill()
				_ = os.RemoveAll(f.cgroupDir(p.unit))
				return err
			},
			procRoot:     f.procRoot,
			cgroupRoot:   f.cgroupRoot,
			pollInterval: 10 * time.Millisecond,
		},
	}, f
}

func launchUnit(t *testing.T, cfg UnitConfig) *unitProcess {
	t.Helper()
	p, err := UnitLauncher(cfg)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = p.Kill()
		_ = p.Conn().Close()
		<-p.Done()
	})
	return p.(*unitProcess)
}

func TestLockdownPropertiesExact(t *testing.T) {
	got := lockdownProperties(UnitConfig{Prefix: "csm-parse-worker-mail0", MemoryLimit: 512 << 20, FileSizeLimit: 64 << 20})
	want := []string{
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
		"SystemCallFilter=~personality",
		"SystemCallErrorNumber=EPERM",
		"MemoryAccounting=yes",
		"MemoryLimit=536870912",
		"MemoryMax=536870912",
		"MemorySwapMax=0",
		"TasksMax=64",
		"LimitNOFILE=256",
		"LimitCORE=0",
		"LimitFSIZE=67108864",
		"CPUWeight=50",
		"OOMScoreAdjust=1000",
		`Slice=system-csm\x2dparse\x2dworker\x2dmail0.slice`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("properties = %q", got)
	}
}

func TestUnitLauncherServesRequests(t *testing.T) {
	cfg, _ := fakeUnitConfig(t, "1")
	s, err := New(Config{Name: "unit worker", Launch: UnitLauncher(cfg), Timeout: 5 * time.Second, Limits: cfg.Limits})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	var got struct{ PID int }
	_, _, err = s.Call(context.Background(), Frame{Op: "sleep", Payload: json.RawMessage(`0`)}, nil, func(reply Frame, _ []*os.File) (bool, error) {
		return false, json.Unmarshal(reply.Payload, &got)
	})
	if err != nil {
		t.Fatal(err)
	}
	if st := s.Stats(); got.PID == 0 || st.LastPID != got.PID {
		t.Fatalf("LastPID = %d, helper pid %d", st.LastPID, got.PID)
	}
}

func TestUnitLauncherSetsSliceCPUWeight(t *testing.T) {
	cfg, _ := fakeUnitConfig(t, "1")
	cfg.hooks.configureSlice = nil
	dir := t.TempDir()
	args := filepath.Join(dir, "args")
	command := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CSM_TEST_SYSTEMCTL_ARGS\"\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(command), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CSM_TEST_SYSTEMCTL_ARGS", args)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	launchUnit(t, cfg)
	b, err := os.ReadFile(args)
	if err != nil {
		t.Fatalf("slice CPU weight was not configured: %v", err)
	}
	want := "set-property\n--runtime\n" + unitSlice(cfg.Prefix) + "\nCPUWeight=50\n"
	if string(b) != want {
		t.Fatalf("systemctl arguments = %q, want %q", b, want)
	}
}

func TestUnitLauncherRejectsSliceSetupFailure(t *testing.T) {
	cfg, f := fakeUnitConfig(t, "1")
	want := errors.New("cannot configure slice")
	cfg.hooks.configureSlice = func(ctx context.Context, name string) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("slice setup has no startup deadline")
		}
		return want
	}
	if p, err := UnitLauncher(cfg)(context.Background()); p != nil || !errors.Is(err, want) {
		t.Fatalf("launch = %v, %v; want slice setup failure", p, err)
	}
	if got := len(f.kills()); got != 0 {
		t.Fatalf("started a worker before configuring its slice: %d kills", got)
	}
}

func TestUnitLauncherSystemdRunExitsBeforeHello(t *testing.T) {
	cfg, f := fakeUnitConfig(t, "exit-now")
	launch := UnitLauncher(cfg)
	for range 2 {
		start := time.Now()
		_, err := launch(context.Background())
		if err == nil || !strings.Contains(err.Error(), "isolation unavailable") {
			t.Fatalf("launch = %v", err)
		}
		if took := time.Since(start); took > 2*time.Second {
			t.Fatalf("launch failed after %s; it waited out the start timeout", took)
		}
	}
	killed := f.waitKills(t, 2)
	if killed[0].unit == killed[1].unit {
		t.Fatalf("two launches reused unit %s", killed[0].unit)
	}
}

func TestUnitLauncherRejectsWrongProtocol(t *testing.T) {
	cfg, f := fakeUnitConfig(t, "2")
	if _, err := UnitLauncher(cfg)(context.Background()); err == nil || !strings.Contains(err.Error(), "protocol 2, want 1") {
		t.Fatalf("launch = %v", err)
	}
	f.waitKills(t, 1)
}

func TestUnitLauncherMainPIDFailure(t *testing.T) {
	cfg, f := fakeUnitConfig(t, "1")
	cfg.hooks.mainPID = func(context.Context, *unitProcess) (int, error) { return 0, errors.New("no D-Bus") }
	if _, err := UnitLauncher(cfg)(context.Background()); err == nil || !strings.Contains(err.Error(), "isolation unavailable") {
		t.Fatalf("launch = %v", err)
	}
	p := f.waitKills(t, 1)[0]
	select {
	case <-p.Done():
	default:
		t.Fatal("launch returned before the failed unit was reaped")
	}
}

func TestUnitProcessKillDoesNotBlock(t *testing.T) {
	conn, childFile, err := workerSocket()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	defer childFile.Close()
	release := make(chan struct{})
	defer close(release)
	p := &unitProcess{unit: "u", conn: conn, done: make(chan struct{}), killUnit: func(context.Context, *unitProcess) error {
		<-release
		return nil
	}}
	start := time.Now()
	if err := p.Kill(); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Fatalf("Kill blocked for %s", took)
	}
}

func TestUnitLauncherUnitNamePattern(t *testing.T) {
	cfg, _ := fakeUnitConfig(t, "1")
	p := launchUnit(t, cfg)
	if !regexp.MustCompile(`^csm-parse-worker-zip0-[0-9]+$`).MatchString(p.unit) {
		t.Fatalf("unit name %q", p.unit)
	}
}

// unitCommand writes an executable with mode in a directory with dirMode, and
// opens the test's own temporary directories to other users.
func unitCommand(t *testing.T, mode, dirMode os.FileMode) string {
	t.Helper()
	root := t.TempDir()
	for dir := root; dir != "/" && dir != filepath.Dir(os.TempDir()); dir = filepath.Dir(dir) {
		st, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o001 == 0 {
			if err := os.Chmod(dir, st.Mode().Perm()|0o011); err != nil {
				t.Skipf("cannot open %s to others: %v", dir, err)
			}
		}
	}
	dir := filepath.Join(root, "bin")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "csm")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	return path
}

func TestCheckUnitCommand(t *testing.T) {
	if err := CheckUnitCommand(unitCommand(t, 0o711, 0o711)); err != nil {
		t.Fatalf("execute-only binary in a searchable directory: %v", err)
	}
	if err := CheckUnitCommand(unitCommand(t, 0o700, 0o755)); err == nil || !strings.Contains(err.Error(), "0700") {
		t.Fatalf("owner-only binary: %v", err)
	}
	if err := CheckUnitCommand(unitCommand(t, 0o711, 0o700)); err == nil || !strings.Contains(err.Error(), "bin") {
		t.Fatalf("owner-only directory: %v", err)
	}
	if err := CheckUnitCommand("csm"); err == nil {
		t.Fatal("relative command accepted")
	}
}

func TestLockdownPropertiesInaccessiblePaths(t *testing.T) {
	cfg := UnitConfig{Prefix: "csm-parse-worker-mail0", MemoryLimit: 512 << 20, FileSizeLimit: 64 << 20,
		InaccessiblePaths: []string{"/home3", "/home2", "/home2", "", "rel", "/a b", "/x/../y", "/x/", "/", `/q"`, "/q'", `/q\n`, "/p%h", "/c\x01", "/c\x7f", "/c\r", "/c\t", "/c\n"}}
	var got []string
	for _, p := range lockdownProperties(cfg) {
		if strings.HasPrefix(p, "InaccessiblePaths=") {
			got = append(got, p)
		}
	}
	want := []string{"InaccessiblePaths=-/home2", "InaccessiblePaths=-/home3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("InaccessiblePaths properties = %q, want %q", got, want)
	}
}

type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (c *logCapture) logf(format string, args ...any) {
	c.mu.Lock()
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
	c.mu.Unlock()
}

func (c *logCapture) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...)
}

// Worker output reaches the daemon's log quoted and bounded: a compromised
// worker must not forge log lines or flood the journal.
func TestUnitWorkerStderrQuotedAndCapped(t *testing.T) {
	var in strings.Builder
	in.WriteString("ok\n")
	in.WriteString("\x1b[31mred\n")
	in.WriteString(strings.Repeat("L", 2048) + "\n")
	for range 200 { // 100 KiB that survives the per-line cut
		in.WriteString(strings.Repeat("f", 511) + "\n")
	}
	var c logCapture
	logWorkerOutput(strings.NewReader(in.String()), "csm-parse-worker-mail0-1", c.logf)
	lines := c.all()
	if len(lines) < 3 || lines[0] != `csm-parse-worker-mail0-1: "ok"` || lines[1] != `csm-parse-worker-mail0-1: "\x1b[31mred"` {
		t.Fatalf("first lines = %q", lines[:min(3, len(lines))])
	}
	if lines[2] != `csm-parse-worker-mail0-1: "`+strings.Repeat("L", 512)+`"` {
		t.Fatalf("long line not cut to 512 bytes: %d bytes logged", len(lines[2]))
	}
	logged := 0
	for i, line := range lines[:len(lines)-1] {
		quoted := strings.TrimPrefix(line, "csm-parse-worker-mail0-1: ")
		raw, err := strconv.Unquote(quoted)
		if err != nil || len(raw) > 512 {
			t.Fatalf("line %d %q: not a quoted line of at most 512 bytes", i, line)
		}
		logged += len(raw)
	}
	if logged > 64<<10 {
		t.Fatalf("logged %d bytes of worker output, want at most %d", logged, 64<<10)
	}
	if last := lines[len(lines)-1]; last != "csm-parse-worker-mail0-1: further output dropped" {
		t.Fatalf("last line = %q, want the drop notice", last)
	}
}

// The launcher pipes a real worker's stderr through the same logger.
func TestUnitWorkerStderrReachesLog(t *testing.T) {
	cfg, _ := fakeUnitConfig(t, "stderr-then-exit")
	var c logCapture
	cfg.Log = c.logf
	if _, err := UnitLauncher(cfg)(context.Background()); err == nil {
		t.Fatal("a worker that exits before hello was handed out")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		joined := strings.Join(c.all(), "\n")
		if strings.Contains(joined, `: "hello from stderr"`) && strings.Contains(joined, `: "\x1b[31mforged"`) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker stderr not logged quoted: %q", c.all())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Empty lines cost log lines too: a worker printing only newlines must hit
// the same budget instead of flooding the journal.
func TestUnitWorkerStderrEmptyLinesCharged(t *testing.T) {
	var c logCapture
	logWorkerOutput(strings.NewReader(strings.Repeat("\n", 1<<20)), "csm-parse-worker-mail0-1", c.logf)
	lines := c.all()
	if len(lines) != 1 || lines[0] != "csm-parse-worker-mail0-1: further output dropped" {
		t.Fatalf("logged %d lines for empty output, want only the drop notice", len(lines))
	}
}

// Many tiny lines cost journal entries, not bytes: a worker printing one
// byte per line must not turn 64 KiB into tens of thousands of log lines.
func TestUnitWorkerStderrLineCountCapped(t *testing.T) {
	var c logCapture
	logWorkerOutput(strings.NewReader(strings.Repeat("x\n", 100000)), "csm-parse-worker-mail0-1", c.logf)
	lines := c.all()
	if len(lines) > maxWorkerLogLines+1 || lines[len(lines)-1] != "csm-parse-worker-mail0-1: further output dropped" {
		t.Fatalf("logged %d lines, want at most %d plus the drop notice", len(lines), maxWorkerLogLines)
	}
	total := 0
	for _, l := range lines {
		total += len(l) + 1
	}
	if total > 64<<10 {
		t.Fatalf("logged %d bytes, want at most %d", total, 64<<10)
	}
}
