package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// newWatcherForTest constructs a sigWatcher whose cfgFunc and
// storeFunc resolve to fresh per-test instances. Returns the cfg by
// value so tests can mutate Detection.RescanOnSignatureUpdate to
// exercise the kill switch; the watcher reads it through the
// closure on every tick.
func newWatcherForTest(t *testing.T) (w *sigWatcher, rulesDir string, alertCh chan alert.Finding, flag *atomic.Bool, cfg *config.Config, sdb *store.DB) {
	t.Helper()

	rulesDir = t.TempDir()
	stateDir := t.TempDir()

	var err error
	sdb, err = store.Open(stateDir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = sdb.Close() })

	cfg = &config.Config{}
	cfg.Signatures.RulesDir = rulesDir

	flag = &atomic.Bool{}
	alertCh = make(chan alert.Finding, 16)

	w = newSigWatcher(
		func() *config.Config { return cfg },
		func() *store.DB { return sdb },
		flag,
		alertCh,
	)
	return
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
	w, rulesDir, alertCh, flag, _, sdb := newWatcherForTest(t)

	writeRule(t, rulesDir, "malware.yml", "rules: []", time.Now().Add(-time.Hour))
	writeRule(t, rulesDir, "phish.yara", "rule a {}", time.Now().Add(-time.Hour))

	w.tick()

	if flag.Load() {
		t.Error("first tick set forceFullRescan; should be baseline-only")
	}
	if got := drainAlerts(alertCh); len(got) > 0 {
		t.Errorf("first tick emitted %d alerts; should be silent", len(got))
	}

	_ = w
	// The persisted map should now have both files.
	persisted, err := sdb.GetSignatureFiles()
	if err != nil {
		t.Fatalf("GetSignatureFiles: %v", err)
	}
	if len(persisted) != 2 {
		t.Errorf("persisted = %d entries, want 2", len(persisted))
	}
}

// --- A content change arms the flag ---------------------------------------

func TestSigWatchContentChangeArmsRescan(t *testing.T) {
	w, rulesDir, alertCh, flag, _, _ := newWatcherForTest(t)

	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-2*time.Hour))
	w.tick() // baseline
	if flag.Load() {
		t.Fatalf("flag set after baseline tick")
	}

	writeRule(t, rulesDir, "malware.yml", "v2", time.Now().Add(-time.Hour))
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

// --- A change carrying an older mtime is still a change ------------------

func TestSigWatchBackwardsMtimeArmsRescan(t *testing.T) {
	w, rulesDir, _, flag, _, _ := newWatcherForTest(t)

	writeRule(t, rulesDir, "malware.yml", "v2", time.Now().Add(-time.Hour))
	w.tick()
	flag.Store(false)

	// Someone restored an older ruleset from a backup, mtime and all.
	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-2*time.Hour))
	w.tick()
	if !flag.Load() {
		t.Error("restored older ruleset did not arm rescan")
	}
}

// --- A rewrite with identical content is not a change ---------------------

// Package upgrades and the rules updater rewrite files whose content has not
// changed. Each rewrite moves the mtime, and each full rescan it would arm
// reads every file on the host.
func TestSigWatchIdenticalRewriteDoesNotArmRescan(t *testing.T) {
	w, rulesDir, alertCh, flag, _, sdb := newWatcherForTest(t)

	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-2*time.Hour))
	w.tick()

	newer := time.Now().Add(-time.Hour).Truncate(time.Second)
	path := writeRule(t, rulesDir, "malware.yml", "v1", newer)
	w.tick()

	if flag.Load() {
		t.Error("rewriting identical content armed rescan")
	}
	if got := drainAlerts(alertCh); len(got) > 0 {
		t.Errorf("rewriting identical content emitted %d alerts", len(got))
	}
	persisted, err := sdb.GetSignatureFiles()
	if err != nil {
		t.Fatal(err)
	}
	if !persisted[path].Mtime.Equal(newer) {
		t.Errorf("persisted mtime = %v, want the rewrite's %v so the next tick does not hash again", persisted[path].Mtime, newer)
	}
}

// A failed read is not evidence that rules changed, and must not erase the
// last good hash. Recovery has to compare with that hash even after restart.
func TestSigWatchHashReadFailureRetainsBaseline(t *testing.T) {
	for _, content := range []string{"v1", "v2"} {
		t.Run(content, func(t *testing.T) {
			w, rulesDir, alertCh, flag, cfg, sdb := newWatcherForTest(t)
			stamp := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
			path := writeRule(t, rulesDir, "malware.yml", "v1", stamp)
			w.tick()
			baseline, err := sdb.GetSignatureFiles()
			if err != nil {
				t.Fatal(err)
			}
			if baseline[path].SHA256 == "" {
				t.Fatal("baseline hash missing")
			}

			newer := stamp.Add(time.Hour)
			writeRule(t, rulesDir, "malware.yml", "v1", newer)
			w.hashFile = func(string, os.FileInfo) (string, error) { return "", io.ErrUnexpectedEOF }
			w.tick()
			w.tick()
			if got := drainAlerts(alertCh); flag.Load() || len(got) != 0 {
				t.Error("unreadable identical rules armed a rescan")
			}
			persisted, err := sdb.GetSignatureFiles()
			if err != nil {
				t.Fatal(err)
			}
			if !sameSignatureState(baseline, persisted) || !sameSignatureState(baseline, w.last) {
				t.Error("failed hash replaced the last good file state")
			}

			writeRule(t, rulesDir, "malware.yml", content, newer)
			flag.Store(false)
			w = newSigWatcher(func() *config.Config { return cfg }, func() *store.DB { return sdb }, flag, alertCh)
			w.tick()
			wantChange := content != "v1"
			if flag.Load() != wantChange {
				t.Errorf("recovered content %q: rescan = %v, want %v", content, flag.Load(), wantChange)
			}
			alerts := drainAlerts(alertCh)
			if (wantChange && len(alerts) != 1) || (!wantChange && len(alerts) != 0) {
				t.Errorf("recovered content %q: unexpected alerts: %v", content, alerts)
			}
			flag.Store(false)
			w.tick()
			if flag.Load() || len(drainAlerts(alertCh)) != 0 {
				t.Error("recovered state armed more than once")
			}
		})
	}
}

// An atomic replacement may have exactly the same stamp as the walked file.
// Its bytes must not be committed with metadata obtained from the old inode.
func TestSigWatchReplacementDuringHashRetries(t *testing.T) {
	w, rulesDir, alertCh, flag, _, sdb := newWatcherForTest(t)
	stamp := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	path := writeRule(t, rulesDir, "malware.yml", "v1", stamp)
	w.tick()
	baseline, err := sdb.GetSignatureFiles()
	if err != nil {
		t.Fatal(err)
	}
	newer := stamp.Add(time.Hour)
	writeRule(t, rulesDir, "malware.yml", "v1", newer)
	replacement := writeRule(t, rulesDir, "replacement.tmp", "v2", newer)
	w.hashFile = func(path string, info os.FileInfo) (string, error) {
		if renameErr := os.Rename(replacement, path); renameErr != nil {
			t.Fatal(renameErr)
		}
		return hashRulesFile(path, info)
	}
	w.tick()
	if got := drainAlerts(alertCh); flag.Load() || len(got) != 0 {
		t.Error("unstable file observation armed a rescan")
	}
	persisted, err := sdb.GetSignatureFiles()
	if err != nil {
		t.Fatal(err)
	}
	if !sameSignatureState(baseline, persisted) {
		t.Error("replacement hash was committed with the walked file's metadata")
	}
	w.hashFile = hashRulesFile
	flag.Store(false)
	w.tick()
	if got := drainAlerts(alertCh); !flag.Load() || len(got) != 1 {
		t.Errorf("stable replacement did not arm exactly once: flag %v, alerts %v", flag.Load(), got)
	}
	persisted, err = sdb.GetSignatureFiles()
	if err != nil {
		t.Fatal(err)
	}
	if !persisted[path].Mtime.Equal(newer) || persisted[path].SHA256 == baseline[path].SHA256 {
		t.Errorf("replacement state not persisted: %+v", persisted[path])
	}
}

func TestSigWatchHashRulesFileReadError(t *testing.T) {
	path := t.TempDir()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if digest, err := hashRulesFile(path, info); err == nil || digest != "" {
		t.Fatalf("directory hashed as a rules file: digest %q, error %v", digest, err)
	}
}

func TestSigWatchHashRejectsReplacementFIFO(t *testing.T) {
	dir := t.TempDir()
	path := writeRule(t, dir, "rules.yml", "v1", time.Now())
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	pipe := filepath.Join(dir, "replacement.tmp")
	if err := unix.Mkfifo(pipe, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(pipe, path); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := hashRulesFile(path, info)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("FIFO accepted as a rules file")
		}
	case <-time.After(time.Second):
		// Release a blocking open/read before failing, so the regression
		// itself does not leave a stuck goroutine in the test process.
		writer, err := os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("hash reader did not exit after FIFO was released")
		}
		t.Fatal("hashing blocked on a FIFO replacement")
	}
}

func TestSigWatchSymlinkUsesTargetState(t *testing.T) {
	w, rulesDir, alertCh, flag, _, sdb := newWatcherForTest(t)
	stamp := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	targetDir := t.TempDir()
	target := writeRule(t, targetDir, "rules.txt", "v1", stamp)
	path := filepath.Join(rulesDir, "malware.yml")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	w.tick()
	baseline, err := sdb.GetSignatureFiles()
	if err != nil {
		t.Fatal(err)
	}
	if baseline[path].SHA256 == "" || baseline[path].Size != 2 || !baseline[path].Mtime.Equal(stamp) {
		t.Fatalf("symlink target state not recorded: %+v", baseline[path])
	}
	writeRule(t, targetDir, "rules.txt", "v1", stamp.Add(time.Hour))
	w.tick()
	if got := drainAlerts(alertCh); flag.Load() || len(got) != 0 {
		t.Error("identical symlink target rewrite armed a rescan")
	}
	writeRule(t, targetDir, "rules.txt", "v2", stamp.Add(2*time.Hour))
	w.tick()
	if got := drainAlerts(alertCh); !flag.Load() || len(got) != 1 {
		t.Errorf("changed symlink target did not arm once: flag %v, alerts %v", flag.Load(), got)
	}
}

// --- State written before content hashes were tracked ---------------------

// After an upgrade the store holds mtimes without hashes. A file whose mtime
// still matches is the file that was recorded and must not arm; a file whose
// mtime moved cannot be compared by content, so it arms as it always did.
func TestSigWatchStateWithoutHashes(t *testing.T) {
	w, rulesDir, _, flag, _, sdb := newWatcherForTest(t)

	stamp := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	same := writeRule(t, rulesDir, "same.yml", "v1", stamp)
	moved := writeRule(t, rulesDir, "moved.yml", "v1", time.Now().Add(-time.Hour))
	if err := sdb.PutSignatureFiles(map[string]store.SignatureFileState{
		same:  {Mtime: stamp, Size: -1},
		moved: {Mtime: stamp, Size: -1},
	}); err != nil {
		t.Fatal(err)
	}

	w.tick()
	if !flag.Load() {
		t.Fatal("file whose mtime moved since the hashless record did not arm rescan")
	}

	flag.Store(false)
	if err := os.Remove(moved); err != nil {
		t.Fatal(err)
	}
	writeRule(t, rulesDir, "same.yml", "v1", time.Now())
	w.tick()
	if flag.Load() {
		t.Error("identical rewrite armed rescan; the hashless record was never completed")
	}
}

func TestSigWatchLegacyReadFailureStillUsesMtime(t *testing.T) {
	for _, moved := range []bool{false, true} {
		t.Run(fmt.Sprint(moved), func(t *testing.T) {
			w, rulesDir, alertCh, flag, _, sdb := newWatcherForTest(t)
			stamp := time.Now().Add(-time.Hour).Truncate(time.Second)
			path := writeRule(t, rulesDir, "malware.yml", "v1", stamp)
			recorded := stamp
			if moved {
				recorded = recorded.Add(-time.Hour)
			}
			if err := sdb.PutSignatureFiles(map[string]store.SignatureFileState{
				path: {Mtime: recorded, Size: -1},
			}); err != nil {
				t.Fatal(err)
			}
			w.hashFile = func(string, os.FileInfo) (string, error) { return "", io.ErrUnexpectedEOF }
			w.tick()
			alerts := drainAlerts(alertCh)
			if flag.Load() != moved || (moved && len(alerts) != 1) || (!moved && len(alerts) != 0) {
				t.Errorf("hashless read failure: flag %v, moved %v, alerts %v", flag.Load(), moved, alerts)
			}
			flag.Store(false)
			w.tick()
			w.hashFile = hashRulesFile
			w.tick()
			if got := drainAlerts(alertCh); flag.Load() || len(got) != 0 {
				t.Error("legacy retry or recovery queued another rescan")
			}
			persisted, err := sdb.GetSignatureFiles()
			if err != nil {
				t.Fatal(err)
			}
			if persisted[path].SHA256 == "" {
				t.Error("read recovery did not complete the legacy record")
			}
		})
	}
}

func TestSigWatchLegacyStoreUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name    string
		symlink bool
		moved   bool
	}{
		{name: "unchanged"},
		{name: "moved", moved: true},
		{name: "unchanged symlink", symlink: true},
		{name: "moved symlink", symlink: true, moved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, rulesDir, alertCh, flag, _, sdb := newWatcherForTest(t)
			stamp := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
			var path string
			if tc.symlink {
				target := writeRule(t, t.TempDir(), "rules.txt", "v1", stamp)
				path = filepath.Join(rulesDir, "malware.yml")
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			} else {
				path = writeRule(t, rulesDir, "malware.yml", "v1", stamp)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			recorded := info.ModTime()
			if tc.moved {
				recorded = recorded.Add(-time.Hour)
			}
			// Write the actual on-disk representation used by old builds.
			payload, err := json.Marshal(map[string]time.Time{path: recorded})
			if err != nil {
				t.Fatal(err)
			}
			if closeErr := sdb.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			raw, err := bolt.Open(sdb.Path(), 0600, &bolt.Options{Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = raw.Close() }()
			if writeErr := raw.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte("sig_watch")).Put([]byte("last_mtimes"), payload)
			}); writeErr != nil {
				t.Fatal(writeErr)
			}
			if closeErr := raw.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			reopened, err := store.Open(filepath.Dir(sdb.Path()))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			w.storeFunc = func() *store.DB { return reopened }
			w.tick()
			if flag.Load() != tc.moved {
				t.Errorf("upgrade rescan = %v, want %v", flag.Load(), tc.moved)
			}
			alerts := drainAlerts(alertCh)
			if (tc.moved && len(alerts) != 1) || (!tc.moved && len(alerts) != 0) {
				t.Errorf("unexpected upgrade alerts: %v", alerts)
			}
			persisted, err := reopened.GetSignatureFiles()
			if err != nil {
				t.Fatal(err)
			}
			if persisted[path].SHA256 == "" || persisted[path].Size != 2 || !persisted[path].Mtime.Equal(stamp) {
				t.Errorf("legacy record not completed: %+v", persisted[path])
			}
			flag.Store(false)
			w.tick()
			if got := drainAlerts(alertCh); flag.Load() || len(got) != 0 {
				t.Error("completed legacy record armed again")
			}
		})
	}
}

func TestSigWatchRetriesFailedPersistence(t *testing.T) {
	w, rulesDir, alertCh, flag, _, sdb := newWatcherForTest(t)
	stamp := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	path := writeRule(t, rulesDir, "malware.yml", "v1", stamp)
	w.tick()
	if err := sdb.Close(); err != nil {
		t.Fatal(err)
	}
	writeRule(t, rulesDir, "malware.yml", "v2", stamp.Add(time.Hour))
	w.tick()
	if got := drainAlerts(alertCh); !flag.Load() || len(got) != 1 || w.persisted {
		t.Fatalf("failed write lost update: flag %v, alerts %v, persisted %v", flag.Load(), got, w.persisted)
	}
	flag.Store(false)
	w.tick()
	if got := drainAlerts(alertCh); flag.Load() || len(got) != 0 || w.persisted {
		t.Fatal("unchanged tick duplicated the rescan or marked the failed write as persisted")
	}
	reopened, err := store.Open(filepath.Dir(sdb.Path()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	w.storeFunc = func() *store.DB { return reopened }
	txID := reopened.WriteTxID()
	w.tick()
	persisted, err := reopened.GetSignatureFiles()
	if err != nil {
		t.Fatal(err)
	}
	if !w.persisted || !sameSignatureState(w.last, persisted) || persisted[path].SHA256 == "" {
		t.Fatalf("retry did not persist the changed rules: %v", persisted)
	}
	if reopened.WriteTxID() != txID+1 {
		t.Error("retry did not commit exactly once")
	}
	w.tick()
	if got := drainAlerts(alertCh); flag.Load() || len(got) != 0 || reopened.WriteTxID() != txID+1 {
		t.Error("successful retry duplicated a rescan or a database commit")
	}
}

// --- Unchanged state is not rewritten -------------------------------------

// The watcher ticks every minute. Committing an unchanged map to bbolt each
// time is a synced write for nothing.
func TestSigWatchDoesNotRewriteUnchangedState(t *testing.T) {
	w, rulesDir, _, _, _, sdb := newWatcherForTest(t)

	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-time.Hour))
	w.tick()

	sentinel := map[string]store.SignatureFileState{"/sentinel.yml": {Mtime: time.Unix(1, 0), Size: 1}}
	if err := sdb.PutSignatureFiles(sentinel); err != nil {
		t.Fatal(err)
	}
	w.tick()

	persisted, err := sdb.GetSignatureFiles()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := persisted["/sentinel.yml"]; !ok || len(persisted) != 1 {
		t.Errorf("unchanged tick rewrote the persisted state: %v", persisted)
	}
}

// --- Removed files don't trigger rescan -----------------------------------

func TestSigWatchRemovedFileDoesNotArmRescan(t *testing.T) {
	w, rulesDir, _, flag, _, sdb := newWatcherForTest(t)

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
	persisted, _ := sdb.GetSignatureFiles()
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
	w, rulesDir, _, flag, _, _ := newWatcherForTest(t)

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
	w, rulesDir, _, flag, _, _ := newWatcherForTest(t)

	sub := filepath.Join(rulesDir, "yara-forge", "core")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeRule(t, sub, "core.yar", "rule a {}", time.Now().Add(-2*time.Hour))
	w.tick() // baseline
	flag.Store(false)

	writeRule(t, sub, "core.yar", "rule b {}", time.Now().Add(-time.Hour))
	w.tick()

	if !flag.Load() {
		t.Error("changed rules under a subdirectory did not arm rescan")
	}
}

// --- Restart persistence ---------------------------------------------------

func TestSigWatchRestartDoesNotPhantomRescan(t *testing.T) {
	w, rulesDir, alertCh, _, _, sdb := newWatcherForTest(t)

	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-time.Hour))
	w.tick() // baseline persists mtimes to bbolt

	// Simulate restart by building a fresh watcher pointing at the
	// same store + rulesDir.
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = rulesDir
	flag := &atomic.Bool{}
	w2 := newSigWatcher(
		func() *config.Config { return cfg },
		func() *store.DB { return sdb },
		flag,
		alertCh,
	)
	w2.tick()

	if flag.Load() {
		t.Error("restart with unchanged mtimes triggered a phantom rescan")
	}
}

// --- Extension filter ------------------------------------------------------

func TestSigWatchIgnoresUntrackedExtensions(t *testing.T) {
	w, rulesDir, _, flag, _, _ := newWatcherForTest(t)

	// Create files with extensions outside the tracked set; changes to
	// these should never arm the flag.
	writeRule(t, rulesDir, "README.md", "docs", time.Now().Add(-2*time.Hour))
	writeRule(t, rulesDir, "update.sh", "#!/bin/sh", time.Now().Add(-2*time.Hour))

	w.tick()

	writeRule(t, rulesDir, "README.md", "docs v2", time.Now().Add(-time.Hour))
	writeRule(t, rulesDir, "update.sh", "#!/bin/sh\nexit 0", time.Now().Add(-time.Hour))
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
	w, rulesDir, alertCh, flag, cfg, sdb := newWatcherForTest(t)
	off := false
	cfg.Detection.RescanOnSignatureUpdate = &off

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
	persisted, _ := sdb.GetSignatureFiles()
	if len(persisted) != 0 {
		t.Errorf("disabled watcher persisted %d entries, want 0", len(persisted))
	}
}

// TestSigWatchHotReloadOfRulesDirIsHonored guards against a regression
// where the watcher captured cfg.Signatures.RulesDir at construction
// instead of reading it per tick. After a config swap, the next tick
// must walk the new dir.
func TestSigWatchHotReloadOfRulesDirIsHonored(t *testing.T) {
	w, oldDir, _, flag, cfg, _ := newWatcherForTest(t)
	newDir := t.TempDir()

	// Baseline against oldDir.
	writeRule(t, oldDir, "v1.yml", "v1", time.Now().Add(-time.Hour))
	w.tick()
	flag.Store(false)

	// Hot-reload: cfg now points at newDir. Drop a fresh file there
	// older than its first observation -- since "first observation
	// is silent", this should NOT arm the rescan; the test confirms
	// the watcher is now reading newDir not oldDir by checking that
	// touching oldDir is a no-op.
	cfg.Signatures.RulesDir = newDir
	w.tick() // baseline against newDir

	// Touch a file under oldDir; the watcher should not see it.
	old := writeRule(t, oldDir, "v1.yml", "v2", time.Now())
	_ = os.Chtimes(old, time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	w.tick()

	if flag.Load() {
		t.Error("watcher still walking the OLD rulesDir after hot-reload")
	}

	// Now touch a file under newDir; the watcher should arm.
	newFile := writeRule(t, newDir, "v2.yml", "v1", time.Now().Add(-2*time.Hour))
	w.tick() // observe newFile (silent: first observation)
	if flag.Load() {
		t.Fatal("first observation of new file under newDir armed rescan")
	}
	writeRule(t, newDir, filepath.Base(newFile), "v2", time.Now().Add(time.Minute))
	w.tick()
	if !flag.Load() {
		t.Error("changed rules under newDir did not arm rescan after hot-reload")
	}
}

// TestSigWatchLazyStoreRecoversOnceAvailable guards against a
// regression where store.Global() returning nil at goroutine spawn
// would leave the watcher persistence-blind for its lifetime.
func TestSigWatchLazyStoreRecoversOnceAvailable(t *testing.T) {
	rulesDir := t.TempDir()
	stateDir := t.TempDir()
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = rulesDir
	flag := &atomic.Bool{}
	alertCh := make(chan alert.Finding, 16)

	var sdb *store.DB // initially nil
	w := newSigWatcher(
		func() *config.Config { return cfg },
		func() *store.DB { return sdb },
		flag,
		alertCh,
	)

	writeRule(t, rulesDir, "v1.yml", "v1", time.Now().Add(-time.Hour))
	w.tick() // store nil: in-memory only
	if flag.Load() {
		t.Fatal("nil-store first tick armed rescan")
	}

	// Bring up the store and re-tick. The persisted map should now
	// be populated even though it was nil at construction.
	var err error
	sdb, err = store.Open(stateDir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = sdb.Close() }()

	w.tick()
	persisted, err := sdb.GetSignatureFiles()
	if err != nil {
		t.Fatalf("GetSignatureFiles: %v", err)
	}
	if len(persisted) == 0 {
		t.Error("store became available but watcher never persisted its state")
	}
}

// --- Coalescing multiple changes ------------------------------------------

func TestSigWatchCoalescesMultipleChangesIntoOneFlagOnePerFile(t *testing.T) {
	w, rulesDir, alertCh, flag, _, _ := newWatcherForTest(t)

	for _, name := range []string{"a.yml", "b.yar", "c.yaml"} {
		writeRule(t, rulesDir, name, "v1", time.Now().Add(-2*time.Hour))
	}
	w.tick()
	flag.Store(false)

	for _, name := range []string{"a.yml", "b.yar", "c.yaml"} {
		writeRule(t, rulesDir, name, "v2", time.Now().Add(-time.Hour))
	}
	w.tick()

	if !flag.Load() {
		t.Fatal("multi-file change did not arm rescan")
	}
	alerts := drainAlerts(alertCh)
	if len(alerts) != 3 {
		t.Errorf("alerts emitted = %d, want 3 (one per changed file)", len(alerts))
	}
}
