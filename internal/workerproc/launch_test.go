package workerproc

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestExecLauncherHandsChildOneSocket(t *testing.T) {
	p, err := helperLauncher(t, "sockcheck")(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Kill(); <-p.Done() }()
	defer func() { _ = p.Conn().Close() }()
	if sendErr := SendFrame(p.Conn(), Frame{Op: "check"}, nil, 1<<20); sendErr != nil {
		t.Fatal(sendErr)
	}
	f, _, err := ReceiveFrame(p.Conn(), Limits{MaxFrameBytes: 1 << 20})
	if err != nil || string(f.Payload) != `{"socket":true,"same":true}` {
		t.Fatalf("child fds: %s %v", f.Payload, err)
	}
	if p.PID() <= 0 {
		t.Fatalf("pid %d", p.PID())
	}
}

func TestExecLauncherKillReapsChild(t *testing.T) {
	p, err := helperLauncher(t, "hang")(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Conn().Close() }()
	if err := p.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("killed child not reaped")
	}
	if err := syscall.Kill(p.PID(), 0); err == nil {
		t.Fatal("child still exists after Done")
	}
}

func TestExecLauncherReportsMissingBinary(t *testing.T) {
	if _, err := ExecLauncher(filepath.Join(t.TempDir(), "missing"), nil, nil)(context.Background()); err == nil {
		t.Fatal("missing binary started")
	}
}
