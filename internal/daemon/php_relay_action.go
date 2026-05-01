package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailspool"
)

// msgIDPattern guards exim -Mf invocations against header-injected garbage
// that slipped past parseHeaders. Exim msgIDs are <= 23 chars in practice
// but we accept up to 32 to allow for future format changes; the lower
// bound of 16 rules out any short string an attacker could try to slip in.
var msgIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{16,32}$`)

// eximBinary is resolved at module init via exec.LookPath. Empty means
// auto-action is permanently disabled (a Warning finding is emitted at
// startup -- see Phase O).
//
//nolint:unused // populated in K5 by AutoFreezePHPRelayQueue init via exec.LookPath
var eximBinary string

// actionRateLimiter is a sliding-window counter of exim -M* invocations.
// Per spec: at most maxPerMinute actions in any rolling 60s window.
type actionRateLimiter struct {
	mu         sync.Mutex
	maxPerMin  int
	bucket     int
	refilledAt time.Time
	now        func() time.Time
}

func newActionRateLimiter(maxPerMin int) *actionRateLimiter {
	return &actionRateLimiter{
		maxPerMin: maxPerMin,
		bucket:    maxPerMin,
		now:       time.Now,
	}
}

// consumeN returns true if n tokens were available and consumed.
func (rl *actionRateLimiter) consumeN(n int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	if rl.refilledAt.IsZero() || now.Sub(rl.refilledAt) >= time.Minute {
		rl.bucket = rl.maxPerMin
		rl.refilledAt = now
	}
	if rl.bucket < n {
		return false
	}
	rl.bucket -= n
	return true
}

// freezeErrIsAlreadyGone matches the Exim stderr fragments emitted when
// the message has already left the queue between snapshot and freeze.
// Those are not action failures -- they are normal queue churn.
func freezeErrIsAlreadyGone(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "message not found") ||
		strings.Contains(s, "spool file not found") ||
		strings.Contains(s, "no such message")
}

// spoolScanMatchingScript walks every -H file under spoolRoot, parses
// headers, and returns msgIDs whose X-PHP-Script host:path matches
// scriptKey. Used by AutoFreezePHPRelayQueue when activeMsgs was capped
// or when a late reputation finding has no in-memory activeMsgs left.
//
// Handles BOTH spool layouts:
//
//  1. Split (cPanel default + Exim's split_spool_directory=true): each
//     msgID-H lives under spoolRoot/<hash-char>/. We must descend one
//     level into each subdir.
//  2. Unsplit (some self-hosted Exim builds, smaller cPanel installs
//     where the operator has disabled split_spool_directory): -H files
//     live directly in spoolRoot.
//
// The spec section 5.8 explicitly requires both layouts. We probe each
// entry: if it's a regular -H file at the root, scan it; if it's a
// directory, descend. No probing of /etc/exim or spool config -- the
// filesystem layout is the source of truth.
func spoolScanMatchingScript(spoolRoot string, k scriptKey) []string {
	var out []string
	// #nosec G304 -- spoolRoot is operator-configured / hardcoded to cPanel default.
	entries, err := os.ReadDir(spoolRoot)
	if err != nil {
		return nil
	}
	inspect := func(full string, name string) {
		if !strings.HasSuffix(name, "-H") {
			return
		}
		h, err := emailspool.ParseHeaders(full)
		if err != nil || h.XPHPScript == "" {
			return
		}
		sk, _ := parseXPHPScript(h.XPHPScript)
		if sk != k {
			return
		}
		id := strings.TrimSuffix(name, "-H")
		if msgIDPattern.MatchString(id) {
			out = append(out, id)
		}
	}
	for _, e := range entries {
		full := filepath.Join(spoolRoot, e.Name())
		if e.IsDir() {
			// Split layout: descend one level.
			// #nosec G304 -- spoolRoot is operator-configured / hardcoded to cPanel default.
			files, err := os.ReadDir(full)
			if err != nil {
				continue
			}
			for _, f := range files {
				inspect(filepath.Join(full, f.Name()), f.Name())
			}
			continue
		}
		// Unsplit layout: -H files at the root of spoolRoot.
		inspect(full, e.Name())
	}
	return out
}

// runner abstracts exec.CommandContext so tests can inject a stub.
type runner interface {
	Run(ctx context.Context, bin string, args []string) (stderr string, err error)
}

type defaultRunner struct{}

func (defaultRunner) Run(ctx context.Context, bin string, args []string) (string, error) {
	// #nosec G204 -- bin is the operator-configured exim binary path
	// (autoFreezer.eximBin, default /usr/sbin/exim); args are exim flags +
	// validated msg-IDs from the spool. Not attacker-controlled.
	cmd := exec.CommandContext(ctx, bin, args...)
	var sb strings.Builder
	cmd.Stderr = &sb
	err := cmd.Run()
	return sb.String(), err
}

// auditEntry is the per-action record written by the auditor. K6 will add a
// JSONL serialiser; K5 only constructs the in-memory shape.
type auditEntry struct {
	Ts        time.Time
	MsgID     string
	ScriptKey string
	Path      string
	DryRun    bool
	Exit      int
	Stderr    string
	Action    string // "freeze" | "thaw" | "freeze_dry_run"
}

type auditor interface {
	Write(e auditEntry)
}

// autoFreezer holds the wiring needed to translate findings into exim -Mf
// invocations. Constructed once at daemon start; Apply is invoked per
// post-emit AutoResponse pass.
//
// dryRunFn returns the EFFECTIVE dry-run state. The CLI's runtime
// override + bbolt override + csm.yaml fallback are resolved by the
// PHPRelayController.effectiveDryRun and threaded in via dryRunFn so
// `csm phprelay dry-run on|off|reset` actually changes freeze
// behaviour. autoFreezer never reads cfg.AutoResponse.PHPRelay.DryRun
// directly.
//
//nolint:unused // wired in O2 by daemon controller
type autoFreezer struct {
	scripts   *perScriptWindow
	cfg       *config.Config
	spoolRoot string
	eximBin   string
	runner    runner
	auditor   auditor
	rateLim   *actionRateLimiter
	metrics   *phpRelayMetrics
	dryRunFn  func() bool
}

//nolint:unused // wired in O2 by daemon controller
func newAutoFreezer(scripts *perScriptWindow, cfg *config.Config, spoolRoot, eximBin string, r runner, a auditor, m *phpRelayMetrics, dryRunFn func() bool) *autoFreezer {
	if r == nil {
		r = defaultRunner{}
	}
	rl := newActionRateLimiter(cfg.AutoResponse.PHPRelay.MaxActionsPerMinute)
	if cfg.AutoResponse.PHPRelay.MaxActionsPerMinute <= 0 {
		rl = newActionRateLimiter(60)
	}
	if dryRunFn == nil {
		// Defensive default: if no resolver wired, fall back to the safe
		// YAML-level dry-run state (PHPRelayDryRunEnabled defaults to TRUE).
		dryRunFn = cfg.PHPRelayDryRunEnabled
	}
	return &autoFreezer{
		scripts: scripts, cfg: cfg, spoolRoot: spoolRoot, eximBin: eximBin,
		runner: r, auditor: a, rateLim: rl, metrics: m, dryRunFn: dryRunFn,
	}
}

// Apply iterates findings, snapshots each script's activeMsgs, optionally
// extends with a spool-scan fallback, and freezes via exim -Mf. Returns
// any new findings produced (Warning/Critical for action outcomes). Pure
// from the perspective of finding emission -- caller forwards them to the
// alert pipeline.
//
//nolint:unused // wired in O2 by daemon controller
func (a *autoFreezer) Apply(findings []alert.Finding) []alert.Finding {
	var emitted []alert.Finding
	if !a.cfg.AutoResponse.Enabled || !a.cfg.PHPRelayFreezeEnabled() {
		return nil
	}
	if a.eximBin == "" {
		return nil
	}
	dryRun := a.dryRunFn()
	for _, f := range findings {
		if f.Check != "email_php_relay_abuse" {
			continue
		}
		if !canActOnPath(f.Path) {
			emitted = append(emitted, alert.Finding{
				Severity:  alert.Warning,
				Check:     "email_php_relay_action_skipped",
				Path:      f.Path,
				Message:   fmt.Sprintf("AutoFreeze skipped: path %q has no scriptKey", f.Path),
				Timestamp: time.Now(),
			})
			continue
		}
		s := a.scripts.getOrCreate(scriptKey(f.ScriptKey))
		ids, capped := s.snapshotActiveMsgs()
		if capped || (len(ids) == 0 && f.Path == "reputation") {
			if a.metrics != nil {
				if capped {
					a.metrics.SpoolScanFallbacks.With("capped").Inc()
				} else {
					a.metrics.SpoolScanFallbacks.With("reputation").Inc()
				}
			}
			extra := spoolScanMatchingScript(a.spoolRoot, scriptKey(f.ScriptKey))
			ids = unionStrings(ids, extra)
		}
		if len(ids) == 0 {
			continue
		}
		if dryRun {
			for _, id := range ids {
				a.auditor.Write(auditEntry{
					Ts: time.Now(), MsgID: id, ScriptKey: f.ScriptKey,
					Path: f.Path, DryRun: true, Action: "freeze_dry_run",
				})
			}
			emitted = append(emitted, alert.Finding{
				Severity:  alert.Warning,
				Check:     "email_php_relay_action_dry_run",
				Path:      f.Path,
				Message:   fmt.Sprintf("AutoFreeze dry-run: would freeze %d msgs from %s", len(ids), f.ScriptKey),
				ScriptKey: f.ScriptKey,
				Timestamp: time.Now(),
			})
			continue
		}
		if !a.rateLim.consumeN(len(ids)) {
			emitted = append(emitted, alert.Finding{
				Severity:  alert.Warning,
				Check:     "email_php_relay_rate_limit_hit",
				Path:      f.Path,
				Message:   fmt.Sprintf("AutoFreeze rate limit prevented %d freezes for %s", len(ids), f.ScriptKey),
				ScriptKey: f.ScriptKey,
				Timestamp: time.Now(),
			})
			continue
		}
		var failed []string
		for _, id := range ids {
			if !msgIDPattern.MatchString(id) {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			stderr, err := a.runner.Run(ctx, a.eximBin, []string{"-Mf", id})
			cancel()
			entry := auditEntry{
				Ts: time.Now(), MsgID: id, ScriptKey: f.ScriptKey,
				Path: f.Path, DryRun: false, Stderr: stderr, Action: "freeze",
			}
			if err != nil {
				if freezeErrIsAlreadyGone(stderr) {
					if a.metrics != nil {
						a.metrics.ActionGone.Inc()
					}
					a.auditor.Write(entry)
					continue
				}
				entry.Exit = 1
				failed = append(failed, id)
				if a.metrics != nil {
					a.metrics.Actions.With("freeze", "fail").Inc()
				}
			}
			a.auditor.Write(entry)
			// On successful freeze, drop the id from activeMsgs so we
			// don't re-freeze it on the next finding emission.
			if err == nil {
				if a.metrics != nil {
					a.metrics.Actions.With("freeze", "ok").Inc()
				}
				s.removeActive(id)
			}
		}
		if len(failed) > 0 {
			emitted = append(emitted, alert.Finding{
				Severity:  alert.Critical,
				Check:     "email_php_relay_action_failed",
				Path:      f.Path,
				Message:   fmt.Sprintf("exim -Mf failed for %d msgs from %s", len(failed), f.ScriptKey),
				ScriptKey: f.ScriptKey,
				MsgIDs:    failed,
				Timestamp: time.Now(),
			})
		}
	}
	return emitted
}

// canActOnPath reports whether AutoFreeze can act on a finding's Path.
// volume_account fires per-cpuser without scriptKey; baseline / reputation /
// header / volume / fanout all carry scriptKey.
//
//nolint:unused // wired in O2 by daemon controller
func canActOnPath(p string) bool {
	switch p {
	case "header", "volume", "fanout", "baseline", "reputation":
		return true
	}
	return false
}

//nolint:unused // wired in O2 by daemon controller
func unionStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(a, b...) {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

type structuredAuditor struct {
	mu sync.Mutex
	w  io.Writer
}

func newStructuredAuditor(w io.Writer) *structuredAuditor { return &structuredAuditor{w: w} }

func (a *structuredAuditor) Write(e auditEntry) {
	payload := struct {
		Ts        time.Time `json:"ts"`
		MsgID     string    `json:"msg_id"`
		ScriptKey string    `json:"script_key"`
		Path      string    `json:"path"`
		Action    string    `json:"action"`
		DryRun    bool      `json:"dry_run"`
		Exit      int       `json:"exit"`
		Stderr    string    `json:"stderr,omitempty"`
	}{
		Ts: e.Ts.UTC(), MsgID: e.MsgID, ScriptKey: e.ScriptKey,
		Path: e.Path, Action: e.Action, DryRun: e.DryRun,
		Exit: e.Exit, Stderr: e.Stderr,
	}
	line, err := json.Marshal(payload)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, _ = a.w.Write(line)
	_, _ = a.w.Write([]byte("\n"))
}
