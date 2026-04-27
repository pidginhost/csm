//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// 2026-04-27 forgetwhitecom transfer regression: the inotify forwarder
// watcher fired email_suspicious_forwarder for every external destination
// every time it observed the file. During an account transfer rsync
// writes the entire valiases file at once, and EVERY existing forwarder
// trips a HIGH alert -- buries the operator under noise without any
// indication of what's actually new. The scheduled audit (auditValiasFile)
// already implements first-run baseline using bbolt; the realtime watcher
// must do the same.

func TestForwarderWatcher_FirstRunBaselineSilent(t *testing.T) {
	// Real bbolt-backed store, mirroring the production daemon path.
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "csm.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() { store.SetGlobal(prev) })

	valiases := filepath.Join(tmpDir, "valiases")
	if err := os.MkdirAll(valiases, 0755); err != nil {
		t.Fatal(err)
	}
	domain := "example.com"
	body := []byte("user1: dest1@gmail.com\nuser2: dest2@yahoo.com\n")
	path := filepath.Join(valiases, domain)
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatal(err)
	}

	ch := make(chan alert.Finding, 16)
	fw := &ForwarderWatcher{alertCh: ch}
	t.Setenv("CSM_VALIASES_DIR_OVERRIDE", valiases) // see fw helper below
	withValiasesDir(t, valiases)
	withLocalDomain(t, "example.com")

	fw.handleFileChange(domain)

	select {
	case got := <-ch:
		t.Errorf("first-run baseline must be silent; got: %v %s", got.Severity, got.Message)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestForwarderWatcher_NewExternalDestinationFires(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "csm.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() { store.SetGlobal(prev) })

	valiases := filepath.Join(tmpDir, "valiases")
	if err := os.MkdirAll(valiases, 0755); err != nil {
		t.Fatal(err)
	}
	domain := "example.com"
	path := filepath.Join(valiases, domain)
	if err := os.WriteFile(path, []byte("user1: dest1@gmail.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ch := make(chan alert.Finding, 16)
	fw := &ForwarderWatcher{alertCh: ch}
	withValiasesDir(t, valiases)
	withLocalDomain(t, "example.com")

	// First observation establishes baseline; no alert.
	fw.handleFileChange(domain)
	drainChannel(ch, 50*time.Millisecond)

	// Append a new external forwarder; second observation must alert.
	if err := os.WriteFile(path, []byte("user1: dest1@gmail.com\nattacker: thief@external-evil.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fw.handleFileChange(domain)

	got, ok := waitFinding(ch, 200*time.Millisecond)
	if !ok {
		t.Fatal("expected email_suspicious_forwarder alert on genuinely-new external destination")
	}
	if got.Check != "email_suspicious_forwarder" {
		t.Errorf("Check = %q, want email_suspicious_forwarder", got.Check)
	}
}

// drainChannel discards any pending findings up to the deadline.
func drainChannel(ch chan alert.Finding, d time.Duration) {
	deadline := time.After(d)
	for {
		select {
		case <-ch:
		case <-deadline:
			return
		}
	}
}

func waitFinding(ch chan alert.Finding, d time.Duration) (alert.Finding, bool) {
	select {
	case got := <-ch:
		return got, true
	case <-time.After(d):
		return alert.Finding{}, false
	}
}

// withValiasesDir is a helper that overrides the package-level valiasesDir
// for the duration of a test.
func withValiasesDir(t *testing.T, dir string) {
	prev := valiasesDir
	valiasesDir = dir
	t.Cleanup(func() { valiasesDir = prev })
}

// withLocalDomain ensures the domain is treated as local so destinations
// at it count as internal (parseValias returns "external" -> alert).
func withLocalDomain(t *testing.T, _ string) {
	// loadLocalDomainsForWatcher reads /etc/localdomains by default; for the
	// test we don't need any local-domains entry because dest1@gmail.com etc
	// are external regardless. The helper exists so future tests can extend.
}
