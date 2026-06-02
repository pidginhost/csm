package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// A log watcher built at startup must feed the live (hot-reloaded) config to
// its line handler, not the frozen snapshot it was constructed with. Otherwise
// SIGHUP changes to email thresholds, infra_ips, trusted_countries, and
// suppression settings never reach the log-watching path until a restart.
func TestLogWatcherUsesActiveConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	if err := os.WriteFile(path, []byte("preexisting\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	startup := &config.Config{}
	var seen *config.Config
	handler := func(_ string, cfg *config.Config) []alert.Finding {
		seen = cfg
		return nil
	}

	w, err := NewLogWatcher(path, startup, handler, make(chan alert.Finding, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	active := &config.Config{}
	config.SetActive(active)
	t.Cleanup(func() { config.SetActive(nil) })

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("newline\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	w.readNewLines()

	if seen == nil {
		t.Fatal("handler was not invoked")
	}
	if seen != active {
		t.Fatalf("handler received the startup snapshot, want the active config")
	}
}

// Before any hot-reload publishes an active config, the watcher falls back to
// its startup snapshot rather than passing nil to the handler.
func TestLogWatcherFallsBackToStartupConfig(t *testing.T) {
	config.SetActive(nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	if err := os.WriteFile(path, []byte("preexisting\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	startup := &config.Config{}
	var seen *config.Config
	handler := func(_ string, cfg *config.Config) []alert.Finding {
		seen = cfg
		return nil
	}
	w, err := NewLogWatcher(path, startup, handler, make(chan alert.Finding, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("newline\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	w.readNewLines()

	if seen != startup {
		t.Fatalf("handler should receive the startup snapshot when no active config is set")
	}
}
