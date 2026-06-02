package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/maillog"
)

// A log watcher built at startup must feed the live (hot-reloaded) config to
// its line handler, not the frozen snapshot it was constructed with. Otherwise
// SIGHUP changes to email thresholds, infra_ips, trusted_countries, and
// suppression settings never reach the log-watching path until a restart.
func TestLogWatcherUsesActiveConfig(t *testing.T) {
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })

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
	prev := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prev) })

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

func TestDaemonMailLogDispatchUsesActiveConfig(t *testing.T) {
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })

	startup := &config.Config{}
	active := &config.Config{}
	d := New(startup, nil, nil, "")
	config.SetActive(active)

	var seen *config.Config
	handler := func(_ string, cfg *config.Config) []alert.Finding {
		seen = cfg
		return nil
	}

	if !d.dispatchMailLogLine(maillog.Line{Message: "dovecot: auth failed"}, handler) {
		t.Fatal("mail log dispatch stopped unexpectedly")
	}
	if seen != active {
		t.Fatalf("mail log handler received startup config, want active config")
	}
}
