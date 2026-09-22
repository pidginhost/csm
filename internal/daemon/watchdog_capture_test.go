package daemon

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/sdnotify"
)

// The daemon scrubs the systemd variables from its environment at startup so
// no child can write to the notification socket. The watchdog notifier has to
// read what was captured; reading the environment again finds nothing and
// leaves systemd without keepalives until WatchdogSec restarts the daemon.

func captureNotifyEnv(t *testing.T, usec string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "wdg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "notify")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen unixgram: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	t.Setenv("NOTIFY_SOCKET", path)
	t.Setenv("WATCHDOG_USEC", usec)
	sdnotify.Capture()
	t.Cleanup(sdnotify.Capture)
}

// captureWatchdogEnv puts the daemon in the state it reaches after startup:
// the systemd variables were read and then removed from the environment.
// Passing an empty value leaves that variable unset.
func captureWatchdogEnv(t *testing.T, usec, socket string) {
	t.Helper()
	saved := map[string]string{}
	for _, name := range []string{"WATCHDOG_USEC", "NOTIFY_SOCKET"} {
		if value, ok := os.LookupEnv(name); ok {
			saved[name] = value
		}
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, name := range []string{"WATCHDOG_USEC", "NOTIFY_SOCKET"} {
			_ = os.Unsetenv(name)
		}
		sdnotify.Capture()
		for name, value := range saved {
			_ = os.Setenv(name, value)
		}
	})
	if usec != "" {
		t.Setenv("WATCHDOG_USEC", usec)
	}
	if socket != "" {
		t.Setenv("NOTIFY_SOCKET", socket)
	}
	sdnotify.Capture()
}

func TestWatchdogIntervalHalvesTheTimeoutWithAFloor(t *testing.T) {
	for _, tc := range []struct {
		timeout time.Duration
		want    time.Duration
	}{
		{300 * time.Second, 150 * time.Second},
		{2 * time.Second, 10 * time.Second},
		{30 * time.Second, 15 * time.Second},
	} {
		if got := watchdogInterval(tc.timeout); got != tc.want {
			t.Errorf("watchdogInterval(%s) = %s, want %s", tc.timeout, got, tc.want)
		}
	}
}

func TestWatchdogNotifierRunsOnTheCapturedEnvironment(t *testing.T) {
	captureNotifyEnv(t, "300000000")
	if _, set := os.LookupEnv("NOTIFY_SOCKET"); set {
		t.Fatal("capture left NOTIFY_SOCKET in the environment")
	}

	d := New(&config.Config{}, nil, nil, "")
	d.wg.Add(1)
	done := make(chan struct{})
	go func() {
		d.watchdogNotifier()
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("watchdog notifier exited although the daemon captured a watchdog configuration")
	case <-time.After(200 * time.Millisecond):
	}

	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog notifier did not exit on stop")
	}
}
