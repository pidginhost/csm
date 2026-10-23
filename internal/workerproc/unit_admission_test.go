package workerproc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The fake has already completed hello. Mutations here model what the
// kernel reports before the launcher can hand the worker to its caller.
func TestUnitLauncherRejectsUnsafeMemory(t *testing.T) {
	for _, tc := range []struct {
		name, layout string
		mutate       func(*testing.T, *unitFake, *unitProcess)
	}{
		{"no controller", "v2", func(t *testing.T, f *unitFake, p *unitProcess) {
			proc := filepath.Join(f.procRoot, strconv.Itoa(p.cmd.Process.Pid))
			writeValue(t, filepath.Join(proc, "cgroup"), "1:name=systemd:/system.slice/"+p.unit+".service\n")
			writeValue(t, filepath.Join(proc, "status"), "VmRSS: 1024 kB\nVmSwap: 0 kB\n")
		}},
		{"foreign unit", "v1-memsw", func(t *testing.T, f *unitFake, p *unitProcess) {
			writeValue(t, filepath.Join(f.procRoot, strconv.Itoa(p.cmd.Process.Pid), "cgroup"), "7:memory:/system.slice/other.service\n")
			if err := os.Rename(f.cgroupDir(p.unit), f.cgroupDir("other")); err != nil {
				t.Fatal(err)
			}
		}},
		{"unlimited v2 RAM", "v2", func(t *testing.T, f *unitFake, p *unitProcess) {
			writeValue(t, filepath.Join(f.cgroupDir(p.unit), "memory.max"), "max")
		}},
		{"unlimited v1 RAM", "v1-noswap", func(t *testing.T, f *unitFake, p *unitProcess) {
			writeValue(t, filepath.Join(f.cgroupDir(p.unit), "memory.limit_in_bytes"), "9223372036854771712")
		}},
		{"missing RAM cap", "v2", func(t *testing.T, f *unitFake, p *unitProcess) {
			if err := os.Remove(filepath.Join(f.cgroupDir(p.unit), "memory.max")); err != nil {
				t.Fatal(err)
			}
		}},
		{"over budget at hello", "v1-memsw", func(t *testing.T, f *unitFake, p *unitProcess) {
			writeValue(t, filepath.Join(f.cgroupDir(p.unit), "memory.memsw.usage_in_bytes"), strconv.Itoa(600<<20))
		}},
		{"unreadable usage", "v2", func(t *testing.T, f *unitFake, p *unitProcess) {
			writeValue(t, filepath.Join(f.cgroupDir(p.unit), "memory.current"), "unreadable")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, f := fakeUnitConfig(t, "1")
			f.layout = tc.layout
			cfg.hooks.pollInterval = time.Hour
			mainPID := cfg.hooks.mainPID
			cfg.hooks.mainPID = func(ctx context.Context, p *unitProcess) (int, error) {
				pid, err := mainPID(ctx, p)
				if err == nil {
					tc.mutate(t, f, p)
				}
				return pid, err
			}
			p, err := UnitLauncher(cfg)(context.Background())
			if p != nil {
				_ = p.Kill()
				_ = p.Conn().Close()
				<-p.Done()
				t.Fatalf("unsafe worker admitted: %v", err)
			}
			if err == nil || !strings.Contains(err.Error(), "isolation unavailable") {
				t.Fatalf("launch = %v, want isolation failure", err)
			}
			killed := f.waitKills(t, 1)
			if len(killed) != 1 {
				t.Fatalf("kill calls = %d, want 1", len(killed))
			}
			select {
			case <-killed[0].Done():
			default:
				t.Fatal("failed worker was not reaped")
			}
			if tc.name == "foreign unit" {
				if got := readTrim(t, filepath.Join(f.cgroupDir("other"), "memory.memsw.limit_in_bytes")); got != "9223372036854771712" {
					t.Fatalf("modified a foreign unit's limit: %s", got)
				}
			}
		})
	}
}

func TestUnitLauncherRejectsCanceledAdmission(t *testing.T) {
	cfg, f := fakeUnitConfig(t, "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mainPID := cfg.hooks.mainPID
	cfg.hooks.mainPID = func(ctx context.Context, p *unitProcess) (int, error) {
		pid, err := mainPID(ctx, p)
		cancel()
		return pid, err
	}
	p, err := UnitLauncher(cfg)(ctx)
	if p != nil {
		_ = p.Kill()
		_ = p.Conn().Close()
		<-p.Done()
		t.Fatal("admitted a worker after startup was canceled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("launch = %v, want cancellation", err)
	}
	f.waitKills(t, 1)
}

func TestUnitLauncherClientExitKillsUnit(t *testing.T) {
	cfg, f := fakeUnitConfig(t, "1")
	p := launchUnit(t, cfg)
	if err := p.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("client did not exit")
	}
	// The real service is a child of PID 1, so losing its systemd-run
	// client does not mean the service was stopped.
	f.waitKills(t, 1)
}

func TestUnitProcessKillClosesTransport(t *testing.T) {
	cfg, _ := fakeUnitConfig(t, "1")
	release := make(chan struct{})
	killUnit := cfg.hooks.killUnit
	cfg.hooks.killUnit = func(ctx context.Context, p *unitProcess) error {
		<-release
		return killUnit(ctx, p)
	}
	p := launchUnit(t, cfg)
	t.Cleanup(func() { close(release) })
	if err := p.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := SendFrame(p.Conn(), Frame{Op: "sleep", Payload: []byte(`0`)}, nil, cfg.Limits.MaxFrameBytes); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("request during pending kill = %v, want closed connection", err)
	}
}

func TestUnitLauncherSuccessfulStartReleasesContext(t *testing.T) {
	cfg, _ := fakeUnitConfig(t, "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := UnitLauncher(cfg)(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = p.Kill()
		<-p.Done()
	})
	cancel()
	if err := p.Conn().SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := Handshake(context.Background(), p.Conn(), cfg.Limits, cfg.Protocol); err != nil {
		t.Fatalf("canceling a finished launch broke its worker: %v", err)
	}
}

func TestUnitWatchdogRejectsUnreadableUsage(t *testing.T) {
	cfg, f := fakeUnitConfig(t, "1")
	p := launchUnit(t, cfg)
	writeValue(t, filepath.Join(f.cgroupDir(p.unit), "memory.current"), "unreadable")
	killed := f.waitKills(t, 1)
	if len(killed) != 1 || killed[0] != p {
		t.Fatal("watchdog did not kill the worker with unreadable usage")
	}
}

func TestUnitStartCancellationInterruptsHello(t *testing.T) {
	conn, childFile, err := workerSocket()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	defer childFile.Close()
	child, err := net.FileConn(childFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cfg, _ := fakeUnitConfig(t, "1")
	p := &unitProcess{conn: conn}
	result := make(chan error, 1)
	go func() { result <- p.start(ctx, cfg, cfg.hooks) }()
	if err := child.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReceiveFrame(child.(*net.UnixConn), cfg.Limits); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("start = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		_ = conn.Close()
		<-result
		t.Fatal("canceled startup kept waiting for hello")
	}
}
