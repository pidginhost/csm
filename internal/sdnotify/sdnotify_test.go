package sdnotify

import (
	"os"
	"testing"
)

func TestReady_NoSocketIsNoop(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	os.Unsetenv("NOTIFY_SOCKET")
	sent, err := Ready()
	if err != nil {
		t.Fatalf("expected no error when not under systemd, got %v", err)
	}
	if sent {
		t.Fatalf("expected sent=false when NOTIFY_SOCKET unset")
	}
}

func TestStatus_NoSocketIsNoop(t *testing.T) {
	os.Unsetenv("NOTIFY_SOCKET")
	sent, err := Status("watchers attached: 4")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sent {
		t.Fatalf("expected sent=false")
	}
}

func TestWatchdog_NoSocketIsNoop(t *testing.T) {
	os.Unsetenv("NOTIFY_SOCKET")
	sent, err := Watchdog()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sent {
		t.Fatalf("expected sent=false")
	}
}
