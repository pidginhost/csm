package workerproc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
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
	layout               string
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
	f := &unitFake{layout: "v2", procRoot: t.TempDir(), cgroupRoot: t.TempDir()}
	return UnitConfig{
		Prefix:        "csm-parse-worker-zip0",
		Command:       os.Args[0],
		Args:          append([]string{unitHelperArg}, helperArgs...),
		MemoryLimit:   512 << 20,
		FileSizeLimit: 64 << 20,
		RuntimeMax:    time.Hour,
		StartTimeout:  10 * time.Second,
		Protocol:      1,
		Limits:        Limits{MaxFrameBytes: 1 << 20, MaxFDs: 1},
		hooks: &unitHooks{
			systemdRun: os.Args[0],
			mainPID: func(_ context.Context, p *unitProcess) (int, error) {
				pid := p.cmd.Process.Pid
				return pid, f.writeCgroup(pid, p.unit)
			},
			killUnit: func(_ context.Context, p *unitProcess) error {
				f.mu.Lock()
				f.killed = append(f.killed, p)
				f.mu.Unlock()
				return p.cmd.Process.Kill()
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
	got := lockdownProperties(UnitConfig{MemoryLimit: 512 << 20, FileSizeLimit: 64 << 20})
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
		"LockPersonality=yes",
		"MemoryDenyWriteExecute=yes",
		"UMask=0077",
		"SystemCallFilter=@system-service",
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
