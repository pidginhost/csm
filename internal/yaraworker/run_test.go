package yaraworker

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/yaraipc"
)

// shortTmpDir returns a /tmp/y... dir so the resulting socket path
// stays under macOS's 104-byte sun_path limit.
func shortTmpDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "y")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestRunBindsAndPings(t *testing.T) {
	dir := shortTmpDir(t)
	sock := filepath.Join(dir, "w.sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{SocketPath: sock, RulesDir: ""})
	}()

	// Poll for the socket to appear. Run() binds before Serve spawns
	// any goroutines, so this is a tight bound in practice.
	waitForSocket(t, sock, 2*time.Second)

	c := yaraipc.NewClient(sock, time.Second)
	defer func() { _ = c.Close() }()

	res, err := c.Ping()
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !res.Alive {
		t.Errorf("alive: got false, want true")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

func TestRunRemovesStaleSocket(t *testing.T) {
	dir := shortTmpDir(t)
	sock := filepath.Join(dir, "w.sock")

	// Pretend a prior worker crashed and left the file behind.
	if err := os.WriteFile(sock, []byte("stale"), 0o600); err != nil {
		t.Fatalf("seed stale socket: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{SocketPath: sock, RulesDir: ""})
	}()

	waitForSocket(t, sock, 2*time.Second)

	c := yaraipc.NewClient(sock, time.Second)
	defer func() { _ = c.Close() }()

	if _, err := c.Ping(); err != nil {
		t.Fatalf("Ping after stale-socket cleanup: %v", err)
	}

	cancel()
	<-done
}

func TestRunRefusesEmptySocket(t *testing.T) {
	err := Run(context.Background(), Config{})
	if err == nil {
		t.Fatal("expected error on empty socket path")
	}
}

func waitForSocket(t *testing.T, path string, within time.Duration) {
	t.Helper()
	// Check the file-mode socket bit rather than existence; the
	// stale-socket test seeds a regular file at the same path and
	// needs to block until Run has unlinked + rebound.
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		info, err := os.Stat(path)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("socket did not appear at %s within %s", path, within)
}
