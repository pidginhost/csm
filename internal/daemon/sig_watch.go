package daemon

import (
	"fmt"
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
// daemon's forceFullRescan flag whenever any tracked file's mtime
// advances. The next deep-tier tick reads + clears the flag and runs
// the full account tree instead of the fanotify short-list.
//
// The mtime map is persisted in bbolt (sig_watch bucket) so a daemon
// restart does not look like "all files are new" and trigger a
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
type sigWatcher struct {
	cfg        *config.Config
	rulesDir   string
	rescanFlag *atomic.Bool
	alertCh    chan<- alert.Finding
	store      *store.DB
	interval   time.Duration

	// Initialised on first tick from store.GetSignatureMtimes(); the
	// in-memory map is the authoritative working copy for the loop.
	lastMtimes map[string]time.Time
}

// newSigWatcher constructs a watcher with production defaults.
// Callers can override the interval after construction for tests.
func newSigWatcher(cfg *config.Config, flag *atomic.Bool, alertCh chan<- alert.Finding, sdb *store.DB) *sigWatcher {
	return &sigWatcher{
		cfg:        cfg,
		rulesDir:   cfg.Signatures.RulesDir,
		rescanFlag: flag,
		alertCh:    alertCh,
		store:      sdb,
		interval:   sigWatchInterval,
	}
}

// loadInitial pulls the persisted mtime map into memory. Called once
// before the first tick. A read error here is non-fatal -- the
// watcher operates with an empty map and the next tick re-persists,
// so the cost of a transient bbolt error is at most one phantom
// rescan.
func (w *sigWatcher) loadInitial() {
	if w.store == nil {
		w.lastMtimes = map[string]time.Time{}
		return
	}
	got, err := w.store.GetSignatureMtimes()
	if err != nil {
		csmlog.Warn("sig_watch: loading persisted mtimes", "err", err)
		w.lastMtimes = map[string]time.Time{}
		return
	}
	w.lastMtimes = got
}

// tick performs one walk of the rules dir and arms the rescan flag
// when any tracked file's mtime advances. Removed files drop out of
// the persisted map without triggering a rescan -- the spec calls
// out only mtime-advance as a trigger.
func (w *sigWatcher) tick() {
	if !sigWatchEnabled(w.cfg) || w.rulesDir == "" {
		return
	}
	if w.lastMtimes == nil {
		w.loadInitial()
	}

	current := w.walkRulesDir()
	var changed []sigWatchChange
	for path, mtime := range current {
		old, ok := w.lastMtimes[path]
		switch {
		case !ok:
			// New file. The spec treats first-observation as a
			// non-event so a fresh `update-rules` install does not
			// cause a rescan when the daemon also starts cold.
			// Track the mtime forward without arming.
		case !mtime.Equal(old):
			changed = append(changed, sigWatchChange{Path: path, Old: old, New: mtime})
		}
	}

	w.lastMtimes = current
	if w.store != nil {
		if err := w.store.PutSignatureMtimes(current); err != nil {
			csmlog.Warn("sig_watch: persisting mtimes", "err", err)
		}
	}

	if len(changed) == 0 {
		return
	}
	w.rescanFlag.Store(true)
	for _, c := range changed {
		select {
		case w.alertCh <- alert.Finding{
			Severity:  alert.Warning,
			Check:     "signature_update_rescan_queued",
			Message:   fmt.Sprintf("Signature update detected, full deep rescan queued: %s", filepath.Base(c.Path)),
			Details:   fmt.Sprintf("File: %s\nOld mtime: %s\nNew mtime: %s", c.Path, c.Old.UTC().Format(time.RFC3339), c.New.UTC().Format(time.RFC3339)),
			FilePath:  c.Path,
			Timestamp: time.Now(),
		}:
		default:
			// Alert channel is full; the rescan flag is already set
			// so the operator-visible "what happened" record is the
			// less critical loss here.
		}
	}
}

// walkRulesDir returns mtimes for every signature file under
// w.rulesDir. Sub-directories are walked too -- the YARA Forge
// updater puts files under tier-named subfolders.
func (w *sigWatcher) walkRulesDir() map[string]time.Time {
	out := map[string]time.Time{}
	_ = filepath.Walk(w.rulesDir, func(path string, info os.FileInfo, err error) error {
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
		out[path] = info.ModTime()
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

// sigWatchChange records one mtime advance for the alert detail
// message.
type sigWatchChange struct {
	Path string
	Old  time.Time
	New  time.Time
}

// signatureWatcher is the daemon's signature-watch goroutine. Runs
// until d.stopCh is closed; ticks every sigWatchInterval, sets
// d.forceFullRescan when any tracked rule file's mtime advances.
func (d *Daemon) signatureWatcher() {
	defer d.wg.Done()

	cfg := d.currentCfg()
	if cfg == nil {
		csmlog.Warn("sig_watch: no config available, watcher disabled")
		return
	}

	w := newSigWatcher(cfg, &d.forceFullRescan, d.alertCh, store.Global())

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
			// Pull cfg each tick so a hotreload of
			// detection.rescan_on_signature_update takes effect on
			// the next iteration without a daemon restart.
			w.cfg = d.currentCfg()
			w.tick()
		}
	}
}
