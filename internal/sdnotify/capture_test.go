package sdnotify

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Children inherited NOTIFY_SOCKET from the daemon environment, so every
// subprocess the daemon spawned could write to the notification socket. The
// unit declares NotifyAccess=main, so systemd logged each one as a stray
// notification from a non-main PID.

func notifyListener(t *testing.T) (*net.UnixConn, string) {
	t.Helper()
	// A unix socket path is capped near 108 bytes, and t.TempDir() under a
	// long test name can exceed it.
	dir, err := os.MkdirTemp("", "sdn")
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
	return conn, path
}

func readDatagram(t *testing.T, conn *net.UnixConn) string {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read notification: %v", err)
	}
	return string(buf[:n])
}

func TestCaptureRemovesTheSystemdEnvironment(t *testing.T) {
	_, path := notifyListener(t)
	for name, value := range map[string]string{
		"NOTIFY_SOCKET":  path,
		"WATCHDOG_USEC":  "300000000",
		"WATCHDOG_PID":   "1234",
		"LISTEN_FDS":     "1",
		"LISTEN_PID":     "1234",
		"LISTEN_FDNAMES": "csm.socket",
	} {
		t.Setenv(name, value)
	}

	Capture()

	for _, name := range []string{
		"NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID",
		"LISTEN_FDS", "LISTEN_PID", "LISTEN_FDNAMES",
	} {
		if got, ok := os.LookupEnv(name); ok {
			t.Errorf("%s still in the environment as %q; a child would inherit it", name, got)
		}
	}
}

func TestNotifyUsesTheCapturedSocketAfterTheEnvironmentIsGone(t *testing.T) {
	conn, path := notifyListener(t)
	t.Setenv("NOTIFY_SOCKET", path)
	Capture()

	sent, err := Ready()
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if !sent {
		t.Fatal("Ready reported nothing sent while a captured socket exists")
	}
	if got := readDatagram(t, conn); got != "READY=1" {
		t.Fatalf("notification payload %q, want READY=1", got)
	}
}

func TestStatusUsesTheCapturedSocket(t *testing.T) {
	conn, path := notifyListener(t)
	t.Setenv("NOTIFY_SOCKET", path)
	Capture()

	if _, err := Status("watchers attached: 6"); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got := readDatagram(t, conn); got != "STATUS=watchers attached: 6" {
		t.Fatalf("notification payload %q", got)
	}
}

func TestCaptureWithoutASocketLeavesNotifyANoop(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := os.Unsetenv("NOTIFY_SOCKET"); err != nil {
		t.Fatal(err)
	}
	Capture()

	sent, err := Ready()
	if err != nil {
		t.Fatalf("Ready off systemd should be a silent no-op, got %v", err)
	}
	if sent {
		t.Fatal("Ready claimed a notification was sent without a socket")
	}
}

func TestWatchdogTimeoutComesFromTheCapturedEnvironment(t *testing.T) {
	t.Setenv("WATCHDOG_USEC", "300000000")
	Capture()

	got, ok := WatchdogTimeout()
	if !ok {
		t.Fatal("watchdog reported unconfigured while WATCHDOG_USEC was set")
	}
	if got != 300*time.Second {
		t.Fatalf("watchdog timeout %s, want 5m", got)
	}
}

func TestWatchdogTimeoutUnsetWhenNotConfigured(t *testing.T) {
	if err := os.Unsetenv("WATCHDOG_USEC"); err != nil {
		t.Fatal(err)
	}
	Capture()

	if got, ok := WatchdogTimeout(); ok {
		t.Fatalf("watchdog reported %s as configured without WATCHDOG_USEC", got)
	}
}

func TestEnabledTracksWhetherASocketWasCaptured(t *testing.T) {
	if err := os.Unsetenv("NOTIFY_SOCKET"); err != nil {
		t.Fatal(err)
	}
	Capture()
	if Enabled() {
		t.Fatal("Enabled reported a socket off systemd")
	}

	_, path := notifyListener(t)
	t.Setenv("NOTIFY_SOCKET", path)
	Capture()
	if !Enabled() {
		t.Fatal("Enabled reported no socket after capturing one")
	}
}

// Ported from the daemon's private notify helper, which this package replaced:
// a socket path that does not answer must surface an error, not panic.
func TestNotifyToAMissingSocketReturnsAnError(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "absent"))
	Capture()

	sent, err := Ready()
	if err == nil {
		t.Fatal("writing to an absent notification socket reported success")
	}
	if sent {
		t.Fatal("notification reported as sent to an absent socket")
	}
}
