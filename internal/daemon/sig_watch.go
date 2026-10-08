package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/store"
)

// Signature-update-driven retroactive rescan.
//
// CSM's signature rules update independently of the deep-tier
// scanner. The rolling deep YARA walk reaches every existing file once
// per pass, but a pass spans many deep ticks, so a rules update is only
// applied to all existing files when the walk has come back round to
// where it stood at the update. This watcher makes that point visible.
//
// The watcher polls cfg.Signatures.RulesDir every sigWatchInterval,
// stat()s every *.yaml / *.yml / *.yar / *.yara file, and queues a
// rescan in the store whenever any tracked file's content changes. The
// rolling deep YARA walk (checks.CheckYARADeep) tracks the queued
// generation and clears it once it has scanned every file since then.
//
// A file is hashed only when its mtime or size moved. Package upgrades
// and the rules updater rewrite files whose content is unchanged, so a
// moved mtime alone is not a reason to queue a rescan.
//
// The per-file state is persisted in bbolt (sig_watch bucket) so a
// daemon restart does not look like "all files are new" and trigger a
// phantom rescan on first tick.
//
// The queued rescan is persisted in the same transaction as the state
// that caused it, so a restart cannot keep the new state and drop the
// rescan it calls for.

const sigWatchInterval = 60 * time.Second

var sigWatchExtensions = []string{".yaml", ".yml", ".yar", ".yara"}

// sigWatcher carries the watcher's loop state. The daemon owns one
// instance; the goroutine in (*Daemon).signatureWatcher drives it.
//
// cfg and store are re-resolved per tick, not captured at
// construction. Originally we cached cfg.Signatures.RulesDir and
// store.Global() into struct fields and discovered two ways that
// could go wrong: a hot-reload that changed the rules dir would
// silently keep walking the old path, and a daemon ordering quirk
// where store.Global() is nil at goroutine spawn would leave the
// watcher persistence-blind for the rest of its lifetime. Live
// resolution closes both.
type sigWatcher struct {
	cfgFunc   func() *config.Config
	storeFunc func() *store.DB
	alertCh   chan<- alert.Finding
	interval  time.Duration
	hashFile  func(string, os.FileInfo) (string, error)

	// Initialised on first tick from store.GetSignatureFiles(); the
	// in-memory map is the authoritative working copy for the loop.
	last map[string]store.SignatureFileState
	// loaded distinguishes a successful store read from a baseline built
	// while the store was unavailable. Failed startup reads are retried.
	loaded bool
	// persisted is false until last has been written to bbolt, and again
	// after it changes, so an unchanged tick commits nothing.
	persisted bool
	// queueRescan is true from a detected change until the queued rescan
	// is written with the state, so a failed write is retried with it.
	queueRescan bool
}

// newSigWatcher constructs a watcher with production defaults.
// cfgFunc and storeFunc are called per tick so config hot-reloads
// and lazy bbolt initialisation are picked up automatically.
// Callers can override the interval after construction for tests.
func newSigWatcher(cfgFunc func() *config.Config, storeFunc func() *store.DB, alertCh chan<- alert.Finding) *sigWatcher {
	return &sigWatcher{
		cfgFunc:   cfgFunc,
		storeFunc: storeFunc,
		alertCh:   alertCh,
		interval:  sigWatchInterval,
		hashFile:  hashRulesFile,
	}
}

// loadInitial restores saved work even if earlier ticks ran without a store.
// A corrupt queue must be replaced before accepting the current rule state.
func (w *sigWatcher) loadInitial(sdb *store.DB) {
	_, queueErr := sdb.SignatureRescanPending()
	if queueErr != nil {
		csmlog.Warn("sig_watch: loading queued rescan", "err", queueErr)
		if errors.Is(queueErr, store.ErrSignatureRescanCorrupt) {
			w.queueRescan = true
		}
	}
	got, err := sdb.GetSignatureFiles()
	if err != nil {
		csmlog.Warn("sig_watch: loading persisted state", "err", err)
		return
	}
	if got == nil {
		got = make(map[string]store.SignatureFileState)
	}
	w.persisted = !w.queueRescan
	// Saved comparisons take precedence over a first observation made
	// without the store. Already detected in-memory changes are retained
	// with their owed queue, and newly observed paths keep their baseline.
	for path, state := range w.last {
		if _, exists := got[path]; !exists || w.queueRescan {
			got[path] = state
			w.persisted = false
		}
	}
	w.last = got
	w.loaded = queueErr == nil || errors.Is(queueErr, store.ErrSignatureRescanCorrupt)
}

// tick performs one walk of the rules dir and queues a rescan when any
// tracked file's content changed. Removed files drop out of
// the persisted map without triggering a rescan -- the spec calls out
// only a change to an existing file as a trigger.
func (w *sigWatcher) tick() {
	cfg := w.cfgFunc()
	if !cfg.SignatureRescanEnabled() {
		return
	}
	rulesDir := cfg.Signatures.RulesDir
	if rulesDir == "" {
		return
	}
	sdb := w.storeFunc()

	if !w.loaded && sdb != nil {
		w.loadInitial(sdb)
	}
	if w.last == nil {
		w.last = map[string]store.SignatureFileState{}
	}

	current := walkRulesDir(rulesDir)
	next := make(map[string]store.SignatureFileState, len(current))
	var changed []sigWatchChange
	for path, file := range current {
		info := file.info
		old, seen := w.last[path]
		if seen && old.SHA256 != "" && old.Size == info.Size() && old.Mtime.Equal(info.ModTime()) {
			next[path] = old
			continue
		}
		digest, err := w.hashFile(path, info)
		if err != nil {
			csmlog.Warn("sig_watch: hashing rules", "path", path, "err", err)
			if !seen {
				continue
			}
			// Keep the last good comparison point, including its stamp, so
			// the next tick retries instead of accepting an unreadable update.
			if old.SHA256 != "" {
				next[path] = old
				continue
			}
			// With no recorded hash, preserve the legacy mtime fallback
			// even when this read cannot establish a content baseline.
		}
		state := store.SignatureFileState{Mtime: info.ModTime(), Size: info.Size(), SHA256: digest}
		next[path] = state
		switch {
		case !seen:
			// New file. The spec treats first-observation as a
			// non-event so a fresh `update-rules` install does not
			// cause a rescan when the daemon also starts cold.
		case old.SHA256 != "":
			if old.SHA256 != state.SHA256 {
				changed = append(changed, sigWatchChange{Path: path, Old: old.Mtime, New: state.Mtime})
			}
		case old.Size < 0 && old.Mtime.Equal(file.legacyMtime),
			old.Size == state.Size && old.Mtime.Equal(state.Mtime):
			// A legacy record with the same stamp gains a hash without
			// treating the first tick after upgrade as a rules change.
		default:
			// The stamp moved and the contents cannot be compared, so
			// this is treated as a change, as it was before content
			// hashes were tracked.
			changed = append(changed, sigWatchChange{Path: path, Old: old.Mtime, New: state.Mtime})
		}
	}

	if !sameSignatureState(w.last, next) {
		w.persisted = false
	}
	if len(changed) > 0 {
		w.queueRescan = true
	}
	w.last = next
	if sdb != nil && !w.persisted {
		var err error
		if w.queueRescan {
			_, err = sdb.PutSignatureFilesWithRescan(next)
		} else {
			err = sdb.PutSignatureFiles(next)
		}
		if err != nil {
			csmlog.Warn("sig_watch: persisting state", "err", err)
		} else {
			w.persisted = true
			w.queueRescan = false
		}
	}

	for _, c := range changed {
		alert.TryEnqueue(w.alertCh, alert.Finding{
			Severity:  alert.Warning,
			Check:     "signature_update_rescan_queued",
			Message:   fmt.Sprintf("Signature update detected, rescan of existing files queued: %s", filepath.Base(c.Path)),
			Details:   fmt.Sprintf("File: %s\nOld mtime: %s\nNew mtime: %s", c.Path, c.Old.UTC().Format(time.RFC3339), c.New.UTC().Format(time.RFC3339)),
			FilePath:  c.Path,
			Timestamp: time.Now(),
		})
	}
}

// hashRulesFile accepts a hash only while the walked file, the open file and
// the final pathname still identify the same regular file and stamp.
func hashRulesFile(path string, expected os.FileInfo) (string, error) {
	if !expected.Mode().IsRegular() {
		return "", fmt.Errorf("rules file is not regular")
	}
	// A replacement by a FIFO between walk and open must not stall the watcher.
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0) // #nosec G304 -- path comes from walking the operator-configured rules dir and the opened identity is checked below.
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	before, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !sameRulesFile(expected, before) {
		return "", fmt.Errorf("rules file changed before hashing or is not regular")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, before.Size()+1))
	if err != nil {
		return "", err
	}
	after, err := f.Stat()
	if err != nil {
		return "", err
	}
	current, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if n != before.Size() || !sameRulesFile(before, after) || !sameRulesFile(after, current) {
		return "", fmt.Errorf("rules file changed while hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sameRulesFile(a, b os.FileInfo) bool {
	return a.Mode().IsRegular() && b.Mode().IsRegular() && os.SameFile(a, b) &&
		a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func sameSignatureState(a, b map[string]store.SignatureFileState) bool {
	if len(a) != len(b) {
		return false
	}
	for path, x := range a {
		y, ok := b[path]
		if !ok || x.Size != y.Size || x.SHA256 != y.SHA256 || !x.Mtime.Equal(y.Mtime) {
			return false
		}
	}
	return true
}

type sigWatchFile struct {
	info os.FileInfo
	// Old builds recorded the link's mtime for symlinks, not the target's.
	legacyMtime time.Time
}

// walkRulesDir returns the target file info of every signature file under dir.
// Sub-directories are walked too -- the YARA Forge updater puts
// files under tier-named subfolders. Errors during walk (missing
// dir, EACCES on a sub-tree) are swallowed; we want one bad path
// not to crash the watcher or stop sibling traversal.
func walkRulesDir(dir string) map[string]sigWatchFile {
	out := map[string]sigWatchFile{}
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Missing dir or EACCES on a sub-tree -- ignore so the
			// watcher does not crash. We deliberately swallow err
			// instead of returning it; filepath.SkipDir is the
			// idiomatic alternative but we want to keep walking
			// siblings, not the descendants of one bad path.
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !sigWatchExtMatches(ext) {
			return nil
		}
		file := sigWatchFile{info: info, legacyMtime: info.ModTime()}
		if info.Mode()&os.ModeSymlink != 0 {
			if target, err := os.Stat(path); err == nil {
				file.info = target
			}
		}
		out[path] = file
		return nil
	})
	return out
}

// sigWatchExtMatches returns true when ext is one of the file
// extensions the watcher tracks. Lower-case input expected.
func sigWatchExtMatches(ext string) bool {
	for _, want := range sigWatchExtensions {
		if ext == want {
			return true
		}
	}
	return false
}

// sigWatchChange records one changed file for the alert detail
// message.
type sigWatchChange struct {
	Path string
	Old  time.Time
	New  time.Time
}

// signatureWatcher is the daemon's signature-watch goroutine. Runs
// until d.stopCh is closed; ticks every sigWatchInterval and queues a
// rescan when any tracked rule file's content changes.
//
// Cfg and store are accessed via getter closures (not captured
// values) so a hot-reload of signatures.rules_dir takes effect on
// the next tick and a late-initialised bbolt is picked up
// automatically.
func (d *Daemon) signatureWatcher() {
	defer d.wg.Done()

	w := newSigWatcher(
		func() *config.Config { return d.currentCfg() },
		store.Global,
		d.alertCh,
	)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Initial tick on start so the watcher converges quickly when
	// the daemon comes up shortly after an `update-rules` invocation.
	w.tick()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			w.tick()
		}
	}
}
