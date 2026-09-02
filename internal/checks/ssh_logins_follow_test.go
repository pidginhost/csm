package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func sshAcceptedLine(at time.Time, ip string) string {
	return fmt.Sprintf("%s host sshd[1201]: Accepted publickey for root from %s port 51234 ssh2: RSA SHA256:abc",
		at.Format("Jan _2 15:04:05"), ip)
}

func sshFailedLine(at time.Time, ip string) string {
	return fmt.Sprintf("%s host sshd[1202]: Failed password for invalid user admin from %s port 40000 ssh2",
		at.Format("Jan _2 15:04:05"), ip)
}

func sshLoginFindings(findings []alert.Finding) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		if f.Check == "ssh_login_unknown_ip" {
			out = append(out, f)
		}
	}
	return out
}

func useAuthLog(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secure")
	old := authLogPath
	authLogPath = func() string { return path }
	t.Cleanup(func() { authLogPath = old })
	return path
}

func appendLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

// A fixed 100-line tail per cycle is evicted by ordinary brute-force noise:
// one accepted login followed by a few hundred failures never surfaces.
// With a store the check must read the log forward from where it stopped.
func TestCheckSSHLoginsReadsForwardPastBruteForceNoise(t *testing.T) {
	path := useAuthLog(t)
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cfg := &config.Config{}
	now := time.Now()

	lines := []string{sshAcceptedLine(now.Add(-2*time.Minute), "198.51.100.20")}
	for i := 0; i < 300; i++ {
		lines = append(lines, sshFailedLine(now.Add(-time.Minute), "203.0.113.77"))
	}
	appendLines(t, path, lines...)

	got := sshLoginFindings(CheckSSHLogins(context.Background(), cfg, store))
	if len(got) != 1 || !strings.Contains(got[0].Message, "198.51.100.20") {
		t.Fatalf("login buried under noise not reported: %+v", got)
	}

	// Forward-only: the same login is not reported again, a new one is.
	if again := sshLoginFindings(CheckSSHLogins(context.Background(), cfg, store)); len(again) != 0 {
		t.Fatalf("already-reported login surfaced again: %+v", again)
	}
	appendLines(t, path, sshAcceptedLine(now, "198.51.100.21"))
	got = sshLoginFindings(CheckSSHLogins(context.Background(), cfg, store))
	if len(got) != 1 || !strings.Contains(got[0].Message, "198.51.100.21") {
		t.Fatalf("new login after the follow point not reported: %+v", got)
	}
}

// The first run catches up on history; logins recorded days ago are not
// "new logins" and must not raise a critical, always-block finding now.
func TestCheckSSHLoginsCatchUpSkipsOldLogins(t *testing.T) {
	path := useAuthLog(t)
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	appendLines(t, path, sshAcceptedLine(time.Now().Add(-72*time.Hour), "198.51.100.22"))
	if got := sshLoginFindings(CheckSSHLogins(context.Background(), &config.Config{}, store)); len(got) != 0 {
		t.Fatalf("three-day-old login reported as new: %+v", got)
	}
}
