package daemon

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// newWatcherForTest constructs a sigWatcher backed by a real bbolt
// store under t.TempDir(), watching a fresh rules directory. The
// returned function writes a signature file with optional content
// and a specific mtime so tests can drive changes deterministically.
func newWatcherForTest(t *testing.T) (*sigWatcher, string, chan alert.Finding, *atomic.Bool) {
	t.Helper()

	rulesDir := t.TempDir()
	stateDir := t.TempDir()

	sdb, err := store.Open(stateDir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = sdb.Close() })

	cfg := &config.Config{}
	cfg.Signatures.RulesDir = rulesDir

	flag := &atomic.Bool{}
	alertCh := make(chan alert.Finding, 16)

	w := newSigWatcher(cfg, flag, alertCh, sdb)
	return w, rulesDir, alertCh, flag
}

// writeRule creates rulesDir/<name> with content and the supplied
// mtime. Returns the absolute path.
func writeRule(t *testing.T, rulesDir, name, content string, mtime time.Time) string {
	t.Helper()
	path := filepath.Join(rulesDir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	return path
}

func drainAlerts(ch chan alert.Finding) []alert.Finding {
	out := []alert.Finding{}
	for {
		select {
		case f := <-ch:
			out = append(out, f)
		default:
			return out
		}
	}
}

// --- First-tick baseline ---------------------------------------------------

func TestSigWatchFirstTickIsBaselineOnly(t *testing.T) {
	w, rulesDir, alertCh, flag := newWatcherForTest(t)

	writeRule(t, rulesDir, "malware.yml", "rules: []", time.Now().Add(-time.Hour))
	writeRule(t, rulesDir, "phish.yara", "rule a {}", time.Now().Add(-time.Hour))

	w.tick()

	if flag.Load() {
		t.Error("first tick set forceFullRescan; should be baseline-only")
	}
	if got := drainAlerts(alertCh); len(got) > 0 {
		t.Errorf("first tick emitted %d alerts; should be silent", len(got))
	}

	// The persisted map should now have both files.
	persisted, err := w.store.GetSignatureMtimes()
	if err != nil {
		t.Fatalf("GetSignatureMtimes: %v", err)
	}
	if len(persisted) != 2 {
		t.Errorf("persisted = %d entries, want 2", len(persisted))
	}
}

// --- mtime advance arms the flag ------------------------------------------

func TestSigWatchMtimeAdvanceArmsRescan(t *testing.T) {
	w, rulesDir, alertCh, flag := newWatcherForTest(t)

	path := writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-2*time.Hour))
	w.tick() // baseline
	if flag.Load() {
		t.Fatalf("flag set after baseline tick")
	}

	// Advance mtime and re-tick.
	newer := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, newer, newer); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	w.tick()

	if !flag.Load() {
		t.Error("forceFullRescan not armed after mtime advance")
	}
	alerts := drainAlerts(alertCh)
	if len(alerts) != 1 {
		t.Fatalf("alerts emitted = %d, want 1", len(alerts))
	}
	if alerts[0].Check != "signature_update_rescan_queued" {
		t.Errorf("alert check = %q, want signature_update_rescan_queued", alerts[0].Check)
	}
}

// --- Backwards mtime motion is also a change ------------------------------

func TestSigWatchBackwardsMtimeArmsRescan(t *testing.T) {
	w, rulesDir, _, flag := newWatcherForTest(t)

	path := writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-time.Hour))
	w.tick()
	flag.Store(false)

	// Backwards motion: someone restored from a backup.
	older := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(path, older, older); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	w.tick()
	if !flag.Load() {
		t.Error("backwards mtime advance did not arm rescan")
	}
}

// --- Removed files don't trigger rescan -----------------------------------

func TestSigWatchRemovedFileDoesNotArmRescan(t *testing.T) {
	w, rulesDir, _, flag := newWatcherForTest(t)

	path := writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-time.Hour))
	writeRule(t, rulesDir, "phish.yml", "v1", time.Now().Add(-time.Hour))
	w.tick()
	flag.Store(false)

	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	w.tick()

	if flag.Load() {
		t.Error("removing a file armed rescan; should be silent per spec")
	}
	persisted, _ := w.store.GetSignatureMtimes()
	if _, still := persisted[path]; still {
		t.Errorf("removed file still in persisted mtime map")
	}
	if len(persisted) != 1 {
		t.Errorf("persisted entries = %d, want 1 (phish.yml)", len(persisted))
	}
}

// --- New file added after baseline is silent ------------------------------

func TestSigWatchNewFilePostBaselineIsSilent(t *testing.T) {
	// Per the spec: first observation of a file is not a trigger.
	// This avoids a fresh `update-rules` install causing a rescan
	// when the daemon also starts cold and the rules dir is brand
	// new.
	w, rulesDir, _, flag := newWatcherForTest(t)

	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-time.Hour))
	w.tick()
	flag.Store(false)

	writeRule(t, rulesDir, "phish.yml", "v1", time.Now().Add(-time.Hour))
	w.tick()

	if flag.Load() {
		t.Error("new file post-baseline armed rescan; spec calls first observation a non-event")
	}
}

// --- Sub-directory walk ---------------------------------------------------

func TestSigWatchTracksSubdirectories(t *testing.T) {
	w, rulesDir, _, flag := newWatcherForTest(t)

	sub := filepath.Join(rulesDir, "yara-forge", "core")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(sub, "core.yar")
	if err := os.WriteFile(path, []byte("rule a {}"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	old := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(path, old, old)

	w.tick() // baseline
	flag.Store(false)

	newer := time.Now().Add(-time.Hour)
	_ = os.Chtimes(path, newer, newer)
	w.tick()

	if !flag.Load() {
		t.Error("mtime advance under a subdirectory did not arm rescan")
	}
}

// --- Restart persistence ---------------------------------------------------

func TestSigWatchRestartDoesNotPhantomRescan(t *testing.T) {
	w, rulesDir, alertCh, _ := newWatcherForTest(t)

	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-time.Hour))
	w.tick() // baseline persists mtimes to bbolt

	// Simulate restart by building a fresh watcher pointing at the
	// same store + rulesDir.
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = rulesDir
	flag := &atomic.Bool{}
	w2 := newSigWatcher(cfg, flag, alertCh, w.store)
	w2.tick()

	if flag.Load() {
		t.Error("restart with unchanged mtimes triggered a phantom rescan")
	}
}

// --- Extension filter ------------------------------------------------------

func TestSigWatchIgnoresUntrackedExtensions(t *testing.T) {
	w, rulesDir, _, flag := newWatcherForTest(t)

	// Create files with extensions outside the tracked set; mtime
	// changes on these should never arm the flag.
	junkPath := writeRule(t, rulesDir, "README.md", "docs", time.Now().Add(-2*time.Hour))
	scriptPath := writeRule(t, rulesDir, "update.sh", "#!/bin/sh", time.Now().Add(-2*time.Hour))

	w.tick()

	newer := time.Now().Add(-time.Hour)
	_ = os.Chtimes(junkPath, newer, newer)
	_ = os.Chtimes(scriptPath, newer, newer)
	w.tick()

	if flag.Load() {
		t.Error("untracked extension changes armed rescan")
	}
}

// --- Kill-switch -----------------------------------------------------------

func TestSigWatchEnabledTriState(t *testing.T) {
	cases := []struct {
		name   string
		setter func(*config.Config)
		want   bool
	}{
		{"nil cfg defaults on", func(*config.Config) {}, true},
		{"nil pointer defaults on", func(*config.Config) {}, true},
		{"explicit true", func(c *config.Config) {
			on := true
			c.Detection.RescanOnSignatureUpdate = &on
		}, true},
		{"explicit false disables", func(c *config.Config) {
			off := false
			c.Detection.RescanOnSignatureUpdate = &off
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &config.Config{}
			c.setter(cfg)
			if got := sigWatchEnabled(cfg); got != c.want {
				t.Errorf("sigWatchEnabled = %v, want %v", got, c.want)
			}
		})
	}

	if !sigWatchEnabled(nil) {
		t.Error("sigWatchEnabled(nil) = false, want true")
	}
}

func TestSigWatchKillSwitchSilencesTick(t *testing.T) {
	w, rulesDir, alertCh, flag := newWatcherForTest(t)
	off := false
	w.cfg.Detection.RescanOnSignatureUpdate = &off

	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-2*time.Hour))
	w.tick()
	// Even if files would otherwise fire, the disabled watcher does
	// nothing -- not even baseline persistence.
	if flag.Load() {
		t.Error("disabled watcher armed rescan")
	}
	if got := drainAlerts(alertCh); len(got) > 0 {
		t.Errorf("disabled watcher emitted alerts: %v", got)
	}
	persisted, _ := w.store.GetSignatureMtimes()
	if len(persisted) != 0 {
		t.Errorf("disabled watcher persisted %d entries, want 0", len(persisted))
	}
}

// --- Coalescing multiple changes ------------------------------------------

func TestSigWatchCoalescesMultipleChangesIntoOneFlagOnePerFile(t *testing.T) {
	w, rulesDir, alertCh, flag := newWatcherForTest(t)

	a := writeRule(t, rulesDir, "a.yml", "v1", time.Now().Add(-2*time.Hour))
	b := writeRule(t, rulesDir, "b.yar", "v1", time.Now().Add(-2*time.Hour))
	c := writeRule(t, rulesDir, "c.yaml", "v1", time.Now().Add(-2*time.Hour))
	w.tick()
	flag.Store(false)

	newer := time.Now().Add(-time.Hour)
	_ = os.Chtimes(a, newer, newer)
	_ = os.Chtimes(b, newer, newer)
	_ = os.Chtimes(c, newer, newer)
	w.tick()

	if !flag.Load() {
		t.Fatal("multi-file change did not arm rescan")
	}
	alerts := drainAlerts(alertCh)
	if len(alerts) != 3 {
		t.Errorf("alerts emitted = %d, want 3 (one per changed file)", len(alerts))
	}
}
