package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/store"
)

// Signature-update-driven retroactive rescan.
//
// CSM's signature rules update independently of the deep-tier
// scanner. Without this watcher, a fresh ruleset only catches files
// that change AFTER the update -- existing files that newly match
// stay silent until the next time they happen to be touched. Real
// attacks aren't that polite.
//
// The watcher polls cfg.Signatures.RulesDir every sigWatchInterval,
// stat()s every *.yaml / *.yml / *.yar / *.yara file, and sets the
// daemon's forceFullRescan flag whenever any tracked file's content
// changes. The next deep-tier tick reads + clears the flag and runs
// the full account tree instead of the fanotify short-list.
//
// A file is hashed only when its mtime or size moved. Package upgrades
// and the rules updater rewrite files whose content is unchanged, and a
// full rescan reads every file on the host, so a moved mtime alone is
// not a reason to arm.
//
// The per-file state is persisted in bbolt (sig_watch bucket) so a
// daemon restart does not look like "all files are new" and trigger a
// phantom rescan on first tick.

const sigWatchInterval = 60 * time.Second

var sigWatchExtensions = []string{".yaml", ".yml", ".yar", ".yara"}

var (
	sigRescansTotalOnce sync.Once
	sigRescansTotal     *metrics.Counter
)

// observeSignatureRescan increments the operator-facing counter the
// first time the watcher arms a rescan in any process lifetime, and
// every subsequent time. Called from the deep-tier path AFTER a full
// retro-sweep completes, so the counter measures completed sweeps,
// not queued ones.
func observeSignatureRescan() {
	sigRescansTotalOnce.Do(func() {
		sigRescansTotal = metrics.NewCounter(
			"csm_signature_rescans_total",
			"Signature-update-driven full deep-tier rescans completed. Incremented when the deep-tier scheduler picks up the forceFullRescan flag set by the signature watcher and finishes a sweep against the new ruleset.",
		)
		metrics.MustRegister("csm_signature_rescans_total", sigRescansTotal)
	})
	sigRescansTotal.Inc()
}

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
	cfgFunc    func() *config.Config
	storeFunc  func() *store.DB
	rescanFlag *atomic.Bool
	alertCh    chan<- alert.Finding
	interval   time.Duration

	// Initialised on first tick from store.GetSignatureFiles(); the
	// in-memory map is the authoritative working copy for the loop.
	last map[string]store.SignatureFileState
	// persisted is false until last has been written to bbolt, and again
	// after it changes, so an unchanged tick commits nothing.
	persisted bool
}

// newSigWatcher constructs a watcher with production defaults.
// cfgFunc and storeFunc are called per tick so config hot-reloads
// and lazy bbolt initialisation are picked up automatically.
// Callers can override the interval after construction for tests.
func newSigWatcher(cfgFunc func() *config.Config, storeFunc func() *store.DB, flag *atomic.Bool, alertCh chan<- alert.Finding) *sigWatcher {
	return &sigWatcher{
		cfgFunc:    cfgFunc,
		storeFunc:  storeFunc,
		rescanFlag: flag,
		alertCh:    alertCh,
		interval:   sigWatchInterval,
	}
}

// loadInitial pulls the persisted state into memory. Called once when
// w.last is nil. A read error here is non-fatal -- the watcher operates
// with an empty map and the next tick re-persists, so the cost of a
// transient bbolt error is at most one phantom rescan.
func (w *sigWatcher) loadInitial(sdb *store.DB) {
	if sdb == nil {
		w.last = map[string]store.SignatureFileState{}
		return
	}
	got, err := sdb.GetSignatureFiles()
	if err != nil {
		csmlog.Warn("sig_watch: loading persisted state", "err", err)
		w.last = map[string]store.SignatureFileState{}
		return
	}
	w.last = got
	w.persisted = true
}

// tick performs one walk of the rules dir and arms the rescan flag
// when any tracked file's content changed. Removed files drop out of
// the persisted map without triggering a rescan -- the spec calls out
// only a change to an existing file as a trigger.
func (w *sigWatcher) tick() {
	cfg := w.cfgFunc()
	if !sigWatchEnabled(cfg) {
		return
	}
	rulesDir := cfg.Signatures.RulesDir
	if rulesDir == "" {
		return
	}
	sdb := w.storeFunc()

	// Defer first-time persistence load until we have a non-nil
	// store. A nil store on the first tick (race against bbolt
	// open) means we operate purely in-memory; once bbolt is up,
	// the next tick triggers loadInitial as if for the first time
	// because last is still nil.
	if w.last == nil && sdb != nil {
		w.loadInitial(sdb)
	}
	if w.last == nil {
		w.last = map[string]store.SignatureFileState{}
	}

	current := walkRulesDir(rulesDir)
	next := make(map[string]store.SignatureFileState, len(current))
	var changed []sigWatchChange
	for path, info := range current {
		old, seen := w.last[path]
		if seen && old.SHA256 != "" && old.Size == info.Size() && old.Mtime.Equal(info.ModTime()) {
			next[path] = old
			continue
		}
		state := store.SignatureFileState{Mtime: info.ModTime(), Size: info.Size(), SHA256: hashRulesFile(path)}
		next[path] = state
		switch {
		case !seen:
			// New file. The spec treats first-observation as a
			// non-event so a fresh `update-rules` install does not
			// cause a rescan when the daemon also starts cold.
		case old.SHA256 != "" && state.SHA256 != "":
			if old.SHA256 != state.SHA256 {
				changed = append(changed, sigWatchChange{Path: path, Old: old.Mtime, New: state.Mtime})
			}
		case old.Mtime.Equal(state.Mtime) && (old.Size < 0 || old.Size == state.Size):
			// Recorded without a hash, or unreadable now: the file
			// still carries the recorded stamp, so it is the file that
			// was seen. The hash, when readable, completes the record.
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
	w.last = next
	if sdb != nil && !w.persisted {
		if err := sdb.PutSignatureFiles(next); err != nil {
			csmlog.Warn("sig_watch: persisting state", "err", err)
		} else {
			w.persisted = true
		}
	}

	if len(changed) == 0 {
		return
	}
	w.rescanFlag.Store(true)
	for _, c := range changed {
		alert.TryEnqueue(w.alertCh, alert.Finding{
			Severity:  alert.Warning,
			Check:     "signature_update_rescan_queued",
			Message:   fmt.Sprintf("Signature update detected, full deep rescan queued: %s", filepath.Base(c.Path)),
			Details:   fmt.Sprintf("File: %s\nOld mtime: %s\nNew mtime: %s", c.Path, c.Old.UTC().Format(time.RFC3339), c.New.UTC().Format(time.RFC3339)),
			FilePath:  c.Path,
			Timestamp: time.Now(),
		})
	}
}

// hashRulesFile returns the hex SHA-256 of a rules file, or "" when it
// cannot be read.
func hashRulesFile(path string) string {
	f, err := os.Open(path) // #nosec G304 -- path comes from walking the operator-configured rules dir.
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
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

// walkRulesDir returns the file info of every signature file under dir.
// Sub-directories are walked too -- the YARA Forge updater puts
// files under tier-named subfolders. Errors during walk (missing
// dir, EACCES on a sub-tree) are swallowed; we want one bad path
// not to crash the watcher or stop sibling traversal.
func walkRulesDir(dir string) map[string]os.FileInfo {
	out := map[string]os.FileInfo{}
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
		out[path] = info
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

// sigWatchEnabled resolves the tri-state cfg flag. Same shape as
// dbObjectScanningEnabled in the checks package: nil = on, *true =
// on, *false = off.
func sigWatchEnabled(cfg *config.Config) bool {
	if cfg == nil {
		return true
	}
	if cfg.Detection.RescanOnSignatureUpdate == nil {
		return true
	}
	return *cfg.Detection.RescanOnSignatureUpdate
}

// sigWatchChange records one changed file for the alert detail
// message.
type sigWatchChange struct {
	Path string
	Old  time.Time
	New  time.Time
}

// signatureWatcher is the daemon's signature-watch goroutine. Runs
// until d.stopCh is closed; ticks every sigWatchInterval, sets
// d.forceFullRescan when any tracked rule file's content changes.
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
		&d.forceFullRescan,
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
