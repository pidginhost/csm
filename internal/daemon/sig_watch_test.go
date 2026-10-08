package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
func newWatcherForTest(t *testing.T) (w *sigWatcher, rulesDir string, alertCh chan alert.Finding, cfg *config.Config, sdb *store.DB) {
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

	alertCh = make(chan alert.Finding, 16)

	w = newSigWatcher(
		func() *config.Config { return cfg },
		func() *store.DB { return sdb },
		alertCh,
	)
	return
}

// rescanQueued reports whether sdb holds a queued rescan.
func rescanQueued(t *testing.T, sdb *store.DB) bool {
	t.Helper()
	gen, err := sdb.SignatureRescanPending()
	if err != nil {
		t.Fatal(err)
	}
	return gen != 0
}

// clearQueuedRescan clears the queued rescan the way the deep YARA walk
// does once it has scanned every file since the update.
func clearQueuedRescan(t *testing.T, sdb *store.DB) {
	t.Helper()
	gen, err := sdb.SignatureRescanPending()
	if err != nil {
		t.Fatal(err)
	}
	if gen == 0 {
		return
	}
	if cleared, err := sdb.ClearSignatureRescan(gen); err != nil || !cleared {
		t.Fatalf("clearing queued rescan %d: %v, %v", gen, cleared, err)
	}
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
	w, rulesDir, alertCh, _, sdb := newWatcherForTest(t)

	writeRule(t, rulesDir, "malware.yml", "rules: []", time.Now().Add(-time.Hour))
	writeRule(t, rulesDir, "phish.yara", "rule a {}", time.Now().Add(-time.Hour))

	w.tick()

	if rescanQueued(t, sdb) {
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

// --- A content change queues a rescan -------------------------------------

func TestSigWatchContentChangeArmsRescan(t *testing.T) {
	w, rulesDir, alertCh, _, sdb := newWatcherForTest(t)

	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-2*time.Hour))
	w.tick() // baseline
	if rescanQueued(t, sdb) {
		t.Fatalf("rescan queued after baseline tick")
	}

	writeRule(t, rulesDir, "malware.yml", "v2", time.Now().Add(-time.Hour))
	w.tick()

	if !rescanQueued(t, sdb) {
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
	w, rulesDir, _, _, sdb := newWatcherForTest(t)

	writeRule(t, rulesDir, "malware.yml", "v2", time.Now().Add(-time.Hour))
	w.tick()
	clearQueuedRescan(t, sdb)

	// Someone restored an older ruleset from a backup, mtime and all.
	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-2*time.Hour))
	w.tick()
	if !rescanQueued(t, sdb) {
		t.Error("restored older ruleset did not arm rescan")
	}
}

// --- A rewrite with identical content is not a change ---------------------

// Package upgrades and the rules updater rewrite files whose content has not
// changed. Each rewrite moves the mtime, and each full rescan it would arm
// reads every file on the host.
func TestSigWatchIdenticalRewriteDoesNotArmRescan(t *testing.T) {
	w, rulesDir, alertCh, _, sdb := newWatcherForTest(t)

	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-2*time.Hour))
	w.tick()

	newer := time.Now().Add(-time.Hour).Truncate(time.Second)
	path := writeRule(t, rulesDir, "malware.yml", "v1", newer)
	w.tick()

	if rescanQueued(t, sdb) {
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
			w, rulesDir, alertCh, cfg, sdb := newWatcherForTest(t)
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
			if got := drainAlerts(alertCh); rescanQueued(t, sdb) || len(got) != 0 {
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
			clearQueuedRescan(t, sdb)
			w = newSigWatcher(func() *config.Config { return cfg }, func() *store.DB { return sdb }, alertCh)
			w.tick()
			wantChange := content != "v1"
			if rescanQueued(t, sdb) != wantChange {
				t.Errorf("recovered content %q: rescan = %v, want %v", content, rescanQueued(t, sdb), wantChange)
			}
			alerts := drainAlerts(alertCh)
			if (wantChange && len(alerts) != 1) || (!wantChange && len(alerts) != 0) {
				t.Errorf("recovered content %q: unexpected alerts: %v", content, alerts)
			}
			clearQueuedRescan(t, sdb)
			w.tick()
			if rescanQueued(t, sdb) || len(drainAlerts(alertCh)) != 0 {
				t.Error("recovered state armed more than once")
			}
		})
	}
}

// An atomic replacement may have exactly the same stamp as the walked file.
// Its bytes must not be committed with metadata obtained from the old inode.
func TestSigWatchReplacementDuringHashRetries(t *testing.T) {
	w, rulesDir, alertCh, _, sdb := newWatcherForTest(t)
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
	if got := drainAlerts(alertCh); rescanQueued(t, sdb) || len(got) != 0 {
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
	clearQueuedRescan(t, sdb)
	w.tick()
	if got := drainAlerts(alertCh); !rescanQueued(t, sdb) || len(got) != 1 {
		t.Errorf("stable replacement did not arm exactly once: queued %v, alerts %v", rescanQueued(t, sdb), got)
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
	w, rulesDir, alertCh, _, sdb := newWatcherForTest(t)
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
	if got := drainAlerts(alertCh); rescanQueued(t, sdb) || len(got) != 0 {
		t.Error("identical symlink target rewrite armed a rescan")
	}
	writeRule(t, targetDir, "rules.txt", "v2", stamp.Add(2*time.Hour))
	w.tick()
	if got := drainAlerts(alertCh); !rescanQueued(t, sdb) || len(got) != 1 {
		t.Errorf("changed symlink target did not arm once: queued %v, alerts %v", rescanQueued(t, sdb), got)
	}
}

// --- State written before content hashes were tracked ---------------------

// After an upgrade the store holds mtimes without hashes. A file whose mtime
// still matches is the file that was recorded and must not arm; a file whose
// mtime moved cannot be compared by content, so it arms as it always did.
func TestSigWatchStateWithoutHashes(t *testing.T) {
	w, rulesDir, _, _, sdb := newWatcherForTest(t)

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
	if !rescanQueued(t, sdb) {
		t.Fatal("file whose mtime moved since the hashless record did not arm rescan")
	}

	clearQueuedRescan(t, sdb)
	if err := os.Remove(moved); err != nil {
		t.Fatal(err)
	}
	writeRule(t, rulesDir, "same.yml", "v1", time.Now())
	w.tick()
	if rescanQueued(t, sdb) {
		t.Error("identical rewrite armed rescan; the hashless record was never completed")
	}
}

func TestSigWatchLegacyReadFailureStillUsesMtime(t *testing.T) {
	for _, moved := range []bool{false, true} {
		t.Run(fmt.Sprint(moved), func(t *testing.T) {
			w, rulesDir, alertCh, _, sdb := newWatcherForTest(t)
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
			if rescanQueued(t, sdb) != moved || (moved && len(alerts) != 1) || (!moved && len(alerts) != 0) {
				t.Errorf("hashless read failure: queued %v, moved %v, alerts %v", rescanQueued(t, sdb), moved, alerts)
			}
			clearQueuedRescan(t, sdb)
			w.tick()
			w.hashFile = hashRulesFile
			w.tick()
			if got := drainAlerts(alertCh); rescanQueued(t, sdb) || len(got) != 0 {
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
			w, rulesDir, alertCh, _, sdb := newWatcherForTest(t)
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
			if rescanQueued(t, reopened) != tc.moved {
				t.Errorf("upgrade rescan = %v, want %v", rescanQueued(t, reopened), tc.moved)
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
			clearQueuedRescan(t, reopened)
			w.tick()
			if got := drainAlerts(alertCh); rescanQueued(t, reopened) || len(got) != 0 {
				t.Error("completed legacy record armed again")
			}
		})
	}
}

func TestSigWatchRetriesFailedPersistence(t *testing.T) {
	w, rulesDir, alertCh, _, sdb := newWatcherForTest(t)
	stamp := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	path := writeRule(t, rulesDir, "malware.yml", "v1", stamp)
	w.tick()
	if err := sdb.Close(); err != nil {
		t.Fatal(err)
	}
	writeRule(t, rulesDir, "malware.yml", "v2", stamp.Add(time.Hour))
	w.tick()
	if got := drainAlerts(alertCh); !w.queueRescan || len(got) != 1 || w.persisted {
		t.Fatalf("failed write lost update: owed %v, alerts %v, persisted %v", w.queueRescan, got, w.persisted)
	}
	w.tick()
	if got := drainAlerts(alertCh); !w.queueRescan || len(got) != 0 || w.persisted {
		t.Fatal("unchanged tick duplicated the rescan, dropped it, or marked the failed write as persisted")
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
	gen, err := reopened.SignatureRescanPending()
	if err != nil || gen == 0 || w.queueRescan {
		t.Fatalf("retry did not queue the owed rescan: generation %d, %v, still owed %v", gen, err, w.queueRescan)
	}
	w.tick()
	again, err := reopened.SignatureRescanPending()
	if got := drainAlerts(alertCh); err != nil || again != gen || len(got) != 0 || reopened.WriteTxID() != txID+1 {
		t.Error("successful retry duplicated a rescan or a database commit")
	}
}

// --- Unchanged state is not rewritten -------------------------------------

// The watcher ticks every minute. Committing an unchanged map to bbolt each
// time is a synced write for nothing.
func TestSigWatchDoesNotRewriteUnchangedState(t *testing.T) {
	w, rulesDir, _, _, sdb := newWatcherForTest(t)

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
	w, rulesDir, _, _, sdb := newWatcherForTest(t)

	path := writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-time.Hour))
	writeRule(t, rulesDir, "phish.yml", "v1", time.Now().Add(-time.Hour))
	w.tick()
	clearQueuedRescan(t, sdb)

	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	w.tick()

	if rescanQueued(t, sdb) {
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
	w, rulesDir, _, _, sdb := newWatcherForTest(t)

	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-time.Hour))
	w.tick()
	clearQueuedRescan(t, sdb)

	writeRule(t, rulesDir, "phish.yml", "v1", time.Now().Add(-time.Hour))
	w.tick()

	if rescanQueued(t, sdb) {
		t.Error("new file post-baseline armed rescan; spec calls first observation a non-event")
	}
}

// --- Sub-directory walk ---------------------------------------------------

func TestSigWatchTracksSubdirectories(t *testing.T) {
	w, rulesDir, _, _, sdb := newWatcherForTest(t)

	sub := filepath.Join(rulesDir, "yara-forge", "core")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeRule(t, sub, "core.yar", "rule a {}", time.Now().Add(-2*time.Hour))
	w.tick() // baseline
	clearQueuedRescan(t, sdb)

	writeRule(t, sub, "core.yar", "rule b {}", time.Now().Add(-time.Hour))
	w.tick()

	if !rescanQueued(t, sdb) {
		t.Error("changed rules under a subdirectory did not arm rescan")
	}
}

// --- Restart persistence ---------------------------------------------------

func TestSigWatchRestartDoesNotPhantomRescan(t *testing.T) {
	w, rulesDir, alertCh, _, sdb := newWatcherForTest(t)

	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-time.Hour))
	w.tick() // baseline persists mtimes to bbolt

	// Simulate restart by building a fresh watcher pointing at the
	// same store + rulesDir.
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = rulesDir
	w2 := newSigWatcher(
		func() *config.Config { return cfg },
		func() *store.DB { return sdb },
		alertCh,
	)
	w2.tick()

	if rescanQueued(t, sdb) {
		t.Error("restart with unchanged mtimes triggered a phantom rescan")
	}
}

// --- Extension filter ------------------------------------------------------

func TestSigWatchIgnoresUntrackedExtensions(t *testing.T) {
	w, rulesDir, _, _, sdb := newWatcherForTest(t)

	// Create files with extensions outside the tracked set; changes to
	// these should never queue a rescan.
	writeRule(t, rulesDir, "README.md", "docs", time.Now().Add(-2*time.Hour))
	writeRule(t, rulesDir, "update.sh", "#!/bin/sh", time.Now().Add(-2*time.Hour))

	w.tick()

	writeRule(t, rulesDir, "README.md", "docs v2", time.Now().Add(-time.Hour))
	writeRule(t, rulesDir, "update.sh", "#!/bin/sh\nexit 0", time.Now().Add(-time.Hour))
	w.tick()

	if rescanQueued(t, sdb) {
		t.Error("untracked extension changes armed rescan")
	}
}

// --- Kill-switch -----------------------------------------------------------

func TestSigWatchKillSwitchSilencesTick(t *testing.T) {
	w, rulesDir, alertCh, cfg, sdb := newWatcherForTest(t)
	off := false
	cfg.Detection.RescanOnSignatureUpdate = &off

	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-2*time.Hour))
	w.tick()
	// Even if files would otherwise fire, the disabled watcher does
	// nothing -- not even baseline persistence.
	if rescanQueued(t, sdb) {
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
	w, oldDir, _, cfg, sdb := newWatcherForTest(t)
	newDir := t.TempDir()

	// Baseline against oldDir.
	writeRule(t, oldDir, "v1.yml", "v1", time.Now().Add(-time.Hour))
	w.tick()
	clearQueuedRescan(t, sdb)

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

	if rescanQueued(t, sdb) {
		t.Error("watcher still walking the OLD rulesDir after hot-reload")
	}

	// Now touch a file under newDir; the watcher should arm.
	newFile := writeRule(t, newDir, "v2.yml", "v1", time.Now().Add(-2*time.Hour))
	w.tick() // observe newFile (silent: first observation)
	if rescanQueued(t, sdb) {
		t.Fatal("first observation of new file under newDir armed rescan")
	}
	writeRule(t, newDir, filepath.Base(newFile), "v2", time.Now().Add(time.Minute))
	w.tick()
	if !rescanQueued(t, sdb) {
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
	alertCh := make(chan alert.Finding, 16)

	var sdb *store.DB // initially nil
	w := newSigWatcher(
		func() *config.Config { return cfg },
		func() *store.DB { return sdb },
		alertCh,
	)

	writeRule(t, rulesDir, "v1.yml", "v1", time.Now().Add(-time.Hour))
	w.tick() // store nil: in-memory only
	if w.queueRescan {
		t.Fatal("nil-store first tick queued a rescan")
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

func TestSigWatchCoalescesMultipleChangesIntoOneRescanOneAlertPerFile(t *testing.T) {
	w, rulesDir, alertCh, _, sdb := newWatcherForTest(t)

	for _, name := range []string{"a.yml", "b.yar", "c.yaml"} {
		writeRule(t, rulesDir, name, "v1", time.Now().Add(-2*time.Hour))
	}
	w.tick()
	clearQueuedRescan(t, sdb)

	for _, name := range []string{"a.yml", "b.yar", "c.yaml"} {
		writeRule(t, rulesDir, name, "v2", time.Now().Add(-time.Hour))
	}
	w.tick()

	if !rescanQueued(t, sdb) {
		t.Fatal("multi-file change did not arm rescan")
	}
	alerts := drainAlerts(alertCh)
	if len(alerts) != 3 {
		t.Errorf("alerts emitted = %d, want 3 (one per changed file)", len(alerts))
	}
}

// --- A queued rescan survives restarts until a sweep completes ------------

// restartWatcher simulates a daemon restart: a fresh watcher over the same
// store and rules dir. It runs the startup tick and reports whether a
// rescan is queued afterwards.
func restartWatcher(t *testing.T, rulesDir string, sdb *store.DB) bool {
	t.Helper()
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = rulesDir
	w := newSigWatcher(
		func() *config.Config { return cfg },
		func() *store.DB { return sdb },
		make(chan alert.Finding, 16),
	)
	w.tick()
	return rescanQueued(t, sdb)
}

func TestSigWatchQueuedRescanSurvivesRestart(t *testing.T) {
	w, rulesDir, _, _, sdb := newWatcherForTest(t)
	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-2*time.Hour))
	w.tick()
	writeRule(t, rulesDir, "malware.yml", "v2", time.Now().Add(-time.Hour))
	w.tick()
	if !rescanQueued(t, sdb) {
		t.Fatal("change did not arm the rescan")
	}

	if !restartWatcher(t, rulesDir, sdb) {
		t.Fatal("restart before the deep tick dropped the queued rescan")
	}
	if !restartWatcher(t, rulesDir, sdb) {
		t.Fatal("a second restart dropped the queued rescan")
	}
}

// Only the deep YARA walk clears the queue, once it has scanned every file
// since the update (see checks.CheckYARADeep). Until then every start keeps
// it; afterwards no start queues it again.
func TestSigWatchRescanQueuedUntilCleared(t *testing.T) {
	w, rulesDir, _, _, sdb := newWatcherForTest(t)
	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-2*time.Hour))
	w.tick()
	writeRule(t, rulesDir, "malware.yml", "v2", time.Now().Add(-time.Hour))
	w.tick()
	gen, err := sdb.SignatureRescanPending()
	if err != nil || gen == 0 {
		t.Fatalf("change did not queue a generation: %d, %v", gen, err)
	}
	if !restartWatcher(t, rulesDir, sdb) {
		t.Fatal("restart before the walk finished dropped the rescan")
	}
	if cleared, err := sdb.ClearSignatureRescan(gen); err != nil || !cleared {
		t.Fatalf("clearing the queued generation: %v, %v", cleared, err)
	}
	if restartWatcher(t, rulesDir, sdb) {
		t.Error("restart after the walk finished queued it again")
	}
}

// A rules change while the walk covers an older one needs its own pass:
// clearing the older generation must not clear it.
func TestSigWatchChangeDuringPassKeepsNewRescan(t *testing.T) {
	w, rulesDir, _, _, sdb := newWatcherForTest(t)
	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-3*time.Hour))
	w.tick()
	writeRule(t, rulesDir, "malware.yml", "v2", time.Now().Add(-2*time.Hour))
	w.tick()
	gen, err := sdb.SignatureRescanPending()
	if err != nil || gen == 0 {
		t.Fatalf("change did not queue a generation: %d, %v", gen, err)
	}

	writeRule(t, rulesDir, "malware.yml", "v3", time.Now().Add(-time.Hour))
	w.tick()
	if cleared, err := sdb.ClearSignatureRescan(gen); err != nil || cleared {
		t.Fatalf("clearing the older generation cleared the newer rescan: %v, %v", cleared, err)
	}
	if !rescanQueued(t, sdb) {
		t.Error("change during the pass did not queue another rescan")
	}
	if !restartWatcher(t, rulesDir, sdb) {
		t.Error("restart lost the newer rescan")
	}
}

// When the store write fails at the change, the retry must still record the
// rescan, or a restart after the retry would forget it.
func TestSigWatchRetriedWriteKeepsRescanQueued(t *testing.T) {
	w, rulesDir, _, _, sdb := newWatcherForTest(t)
	stamp := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	writeRule(t, rulesDir, "malware.yml", "v1", stamp)
	w.tick()
	if err := sdb.Close(); err != nil {
		t.Fatal(err)
	}
	writeRule(t, rulesDir, "malware.yml", "v2", stamp.Add(time.Hour))
	w.tick()
	if !w.queueRescan {
		t.Fatal("change did not keep the rescan owed in memory")
	}
	reopened, err := store.Open(filepath.Dir(sdb.Path()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	w.storeFunc = func() *store.DB { return reopened }
	w.tick()
	if !restartWatcher(t, rulesDir, reopened) {
		t.Error("the retried write did not record the queued rescan")
	}
}

// A rewrite with unchanged content after a completed pass moves the stored
// stamps but is no reason to queue another rescan.
func TestSigWatchIdenticalRewriteAfterSweepQueuesNothing(t *testing.T) {
	w, rulesDir, _, _, sdb := newWatcherForTest(t)
	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-3*time.Hour))
	w.tick()
	writeRule(t, rulesDir, "malware.yml", "v2", time.Now().Add(-2*time.Hour))
	w.tick()
	clearQueuedRescan(t, sdb)

	writeRule(t, rulesDir, "malware.yml", "v2", time.Now().Add(-time.Hour))
	w.tick()
	if rescanQueued(t, sdb) {
		t.Error("identical rewrite queued a rescan")
	}
	if restartWatcher(t, rulesDir, sdb) {
		t.Error("identical rewrite queued a rescan for the next start")
	}
}

func TestSigWatchLazyStoreRestoresSavedWork(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprintf("pending=%v", pending), func(t *testing.T) {
			original, rulesDir, _, cfg, sdb := newWatcherForTest(t)
			stamp := time.Now().Add(-2 * time.Hour)
			writeRule(t, rulesDir, "malware.yml", "v1", stamp)
			original.tick()
			writeRule(t, rulesDir, "malware.yml", "v2", stamp.Add(time.Hour))
			if pending {
				original.tick()
			}

			var available *store.DB
			w := newSigWatcher(func() *config.Config { return cfg }, func() *store.DB { return available }, nil)
			w.tick()
			if w.queueRescan {
				t.Fatal("first observation without a store queued a rescan")
			}
			available = sdb
			w.tick()
			if !rescanQueued(t, sdb) {
				t.Fatal("late store lost the saved queue or comparison baseline")
			}
			if !restartWatcher(t, rulesDir, sdb) {
				t.Fatal("late store recovery did not persist the owed rescan")
			}
		})
	}
}

func TestSigWatchRetriesInitialStoreRead(t *testing.T) {
	original, rulesDir, _, cfg, sdb := newWatcherForTest(t)
	stamp := time.Now().Add(-2 * time.Hour)
	writeRule(t, rulesDir, "malware.yml", "v1", stamp)
	original.tick()
	writeRule(t, rulesDir, "malware.yml", "v2", stamp.Add(time.Hour))
	original.tick()
	if err := sdb.Close(); err != nil {
		t.Fatal(err)
	}
	w := newSigWatcher(func() *config.Config { return cfg }, func() *store.DB { return sdb }, nil)
	w.tick()
	reopened, err := store.Open(filepath.Dir(sdb.Path()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	w.storeFunc = func() *store.DB { return reopened }
	w.tick()
	if !w.loaded || !rescanQueued(t, reopened) {
		t.Fatalf("initial read failure permanently hid the queued rescan: loaded %v", w.loaded)
	}
	if !sameSignatureState(w.last, mustSignatureFiles(t, reopened)) {
		t.Error("the retried read did not adopt the saved comparison baseline")
	}
}

func mustSignatureFiles(t *testing.T, sdb *store.DB) map[string]store.SignatureFileState {
	t.Helper()
	files, err := sdb.GetSignatureFiles()
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestSigWatchCorruptQueueRecovers(t *testing.T) {
	w, rulesDir, _, _, sdb := newWatcherForTest(t)
	stamp := time.Now().Add(-2 * time.Hour)
	writeRule(t, rulesDir, "malware.yml", "v1", stamp)
	w.tick()
	writeRule(t, rulesDir, "malware.yml", "v2", stamp.Add(time.Hour))
	w.tick()
	old, err := sdb.SignatureRescanPending()
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
	err = raw.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("sig_watch")).Put([]byte("rescan"), []byte("{"))
	})
	closeErr := raw.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("corrupt fixture: %v, close: %v", err, closeErr)
	}
	reopened, err := store.Open(filepath.Dir(sdb.Path()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if !restartWatcher(t, rulesDir, reopened) {
		t.Fatal("corrupt queue silently dropped the owed rescan")
	}
	gen, err := reopened.SignatureRescanPending()
	if err != nil || gen <= old {
		t.Fatalf("queue not repaired with a new generation: %d, %v", gen, err)
	}
	if cleared, err := reopened.ClearSignatureRescan(old); err != nil || cleared {
		t.Fatalf("stale pass cleared repaired queue: %v, %v", cleared, err)
	}
	if cleared, err := reopened.ClearSignatureRescan(gen); err != nil || !cleared || restartWatcher(t, rulesDir, reopened) {
		t.Fatalf("repaired queue could not be completed: %v, %v", cleared, err)
	}
}

// Turning rescans off stops the watcher but must not drop or renumber work
// it already queued; the walk resumes it when they are turned back on.
func TestSignatureRescanKillSwitchPreservesQueue(t *testing.T) {
	w, rulesDir, _, cfg, sdb := newWatcherForTest(t)
	stamp := time.Now().Add(-2 * time.Hour)
	writeRule(t, rulesDir, "malware.yml", "v1", stamp)
	w.tick()
	writeRule(t, rulesDir, "malware.yml", "v2", stamp.Add(time.Hour))
	w.tick()
	want, err := sdb.SignatureRescanPending()
	if err != nil || want == 0 {
		t.Fatalf("change did not queue a generation: %d, %v", want, err)
	}
	off := false
	cfg.Detection.RescanOnSignatureUpdate = &off
	w.tick()
	if got, err := sdb.SignatureRescanPending(); err != nil || got != want {
		t.Fatalf("kill switch lost the durable queue: %d, %v", got, err)
	}
	on := true
	cfg.Detection.RescanOnSignatureUpdate = &on
	w.tick()
	if got, err := sdb.SignatureRescanPending(); err != nil || got != want {
		t.Fatalf("reenabling rescans did not resume the queued generation: %d, %v", got, err)
	}
}

func TestSigWatchLazyStoreWithEmptySavedState(t *testing.T) {
	_, rulesDir, _, cfg, sdb := newWatcherForTest(t)
	if _, err := sdb.PutSignatureFilesWithRescan(nil); err != nil {
		t.Fatal(err)
	}
	var available *store.DB
	w := newSigWatcher(func() *config.Config { return cfg }, func() *store.DB { return available }, nil)
	writeRule(t, rulesDir, "malware.yml", "v1", time.Now().Add(-time.Hour))
	w.tick()
	available = sdb
	w.tick()
	if !rescanQueued(t, sdb) || !w.loaded {
		t.Fatal("empty saved state hid the queued rescan")
	}
	files, err := sdb.GetSignatureFiles()
	if err != nil || len(files) != 1 {
		t.Fatalf("late store lost the in-memory baseline: %v, %v", files, err)
	}
}
