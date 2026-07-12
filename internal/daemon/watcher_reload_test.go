package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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

// Run owns the watcher's file and must close it when its loop exits on
// stopCh. Previously the file was closed by a separate Stop() call from the
// shutdown goroutine, which raced readNewLines/reopen on w.file. With Run
// owning the close, no concurrent close happens and -race stays clean.
func TestLogWatcherRunClosesFileOnStop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tail.log")
	if err := os.WriteFile(path, []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	w, err := NewLogWatcher(path, &config.Config{}, func(string, *config.Config) []alert.Finding { return nil }, make(chan alert.Finding, 8))
	if err != nil {
		t.Fatal(err)
	}
	f := w.file

	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		w.Run(stopCh)
		close(done)
	}()

	close(stopCh)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return on stopCh")
	}

	if _, err := f.Stat(); err == nil {
		t.Fatal("Run must close the watcher file on exit, but it is still open")
	}
}

func TestLogWatcherWaitsForCompleteLineBeforeAdvancingOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tail.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var lines []string
	w, err := NewLogWatcher(path, &config.Config{}, func(line string, _ *config.Config) []alert.Finding {
		lines = append(lines, line)
		return nil
	}, make(chan alert.Finding, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("authentication fail"); err != nil {
		t.Fatal(err)
	}
	w.readNewLines()
	if len(lines) != 0 {
		t.Fatalf("partial line was dispatched: %v", lines)
	}
	if w.offset != 0 {
		t.Fatalf("offset advanced over partial line to %d", w.offset)
	}

	if _, err := f.WriteString("ed for alice\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	w.readNewLines()
	if len(lines) != 1 || lines[0] != "authentication failed for alice" {
		t.Fatalf("completed lines = %v, want one reconstructed line", lines)
	}
}

func TestLogWatcherAdvancesOffsetPastCompleteBlankLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tail.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := NewLogWatcher(path, &config.Config{}, func(string, *config.Config) []alert.Finding {
		t.Fatal("blank line must not reach the handler")
		return nil
	}, make(chan alert.Finding, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.readNewLines()
	if w.offset != 1 {
		t.Fatalf("offset after complete blank line = %d, want 1", w.offset)
	}
}
