package checks

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

type wpVerificationBatch struct {
	db          *store.DB
	kind, owner string
	at          time.Time
	paths       map[string]string
	mu          sync.Mutex
	results     map[string]store.WPVerificationResult
}

func newWPVerificationBatch(ctx context.Context, db *store.DB, kind, owner string, configs []string) *wpVerificationBatch {
	at := time.Now()
	if cycle := wpInstallCacheFrom(ctx); cycle != nil {
		at = cycle.started
	}
	b := &wpVerificationBatch{db: db, kind: kind, owner: owner, at: at, paths: make(map[string]string), results: make(map[string]store.WPVerificationResult)}
	for _, path := range configs {
		b.paths[filepath.Dir(path)] = wpConfigUser(filepath.Dir(path))
	}
	return b
}

func (b *wpVerificationBatch) record(path string, result store.WPVerificationResult) {
	b.mu.Lock()
	b.results[path] = result
	b.mu.Unlock()
}

// finish runs after workers join, including on partial discovery or shutdown.
// Attempted sites advance; unattempted sites retain their previous evidence.
func (b *wpVerificationBatch) finish(ctx context.Context, complete bool) error {
	if b.db == nil {
		return nil
	}
	err := b.db.UpdateWPVerification(b.kind, b.at, AccountFromContext(ctx), b.paths, b.results, complete && ctx.Err() == nil)
	if err != nil {
		markCheckIncomplete(ctx, b.owner)
	}
	return err
}

func wpVerificationFindings(ctx context.Context, db *store.DB, kind, owner string, updateErr error) []alert.Finding {
	if db == nil {
		return nil
	}
	check, label := "wp_core_unverified", "core verification"
	if kind == "plugins" {
		check, label = "wp_plugin_inventory_unverified", "plugin inventory"
	}
	rows, err := db.WPVerification(kind)
	if err != nil || updateErr != nil {
		markCheckIncomplete(ctx, owner)
		return []alert.Finding{{Check: check, Severity: alert.Warning, Message: "WordPress " + label + " history unavailable", Details: "CSM could not read or save verification history. Check the state database; previous coverage findings are retained."}}
	}
	paths := make([]string, 0, len(rows))
	for path := range rows {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var findings []alert.Finding
	for _, path := range paths {
		row := rows[path]
		if scope := AccountFromContext(ctx); scope != "" && row.Account != scope {
			continue
		}
		if row.State != "unverified" || row.Failures < 2 {
			continue
		}
		findings = append(findings, alert.Finding{
			Check: check, Severity: alert.Warning,
			Message:  "WordPress " + label + " repeatedly failed: " + strconv.QuoteToASCII(path),
			Details:  fmt.Sprintf("Installation: %s\nLast attempt: %s\nReason: %s\nVerification could not complete in consecutive scan cycles. Check wp-cli and this installation locally; raw command output is not stored.", strconv.QuoteToASCII(path), row.AttemptAt.UTC().Format(time.RFC3339), row.Reason),
			FilePath: path, TenantID: row.Account, DedupKey: path,
		})
	}
	return findings
}

// Integrity warnings can precede a later operational error. Only wp-cli's
// expected checksum-mismatch summary establishes a completed negative check.
func wpCoreVerificationCompleted(err error, out []byte) bool {
	if !commandRefused(err) {
		return false
	}
	completed := false
	for _, line := range strings.Split(strings.ToLower(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "fatal error") || strings.Contains(line, "parse error") {
			return false
		}
		if line == "error: wordpress installation doesn't verify against checksums." {
			completed = true
		} else if strings.HasPrefix(line, "error:") {
			return false
		}
	}
	return completed
}

type wpInventoryError struct {
	err    error
	result store.WPVerificationResult
}

func (e *wpInventoryError) Error() string { return e.result.Reason }
func (e *wpInventoryError) Unwrap() error { return e.err }

// wpVerificationFailure classifies output into fixed reasons. Never copy raw
// PHP output or an exec error into persisted evidence: either may carry secrets.
func wpVerificationFailure(err error, out []byte) store.WPVerificationResult {
	var inventory *wpInventoryError
	if errors.As(err, &inventory) {
		return inventory.result
	}
	result := store.WPVerificationResult{State: "unverified", Reason: "wp-cli could not complete the check"}
	var exit *exec.ExitError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		result.Reason = "wp-cli timed out"
	case errors.Is(err, context.Canceled):
		result.Reason = "wp-cli was interrupted"
	case errors.Is(err, exec.ErrNotFound):
		result.Reason = "wp-cli executable is unavailable"
	case errors.Is(err, errWPInventoryParse):
		result.Reason = "wp-cli returned invalid plugin inventory JSON"
	case errors.Is(err, errWPInventoryNoOutput):
		result.Reason = "wp-cli returned no plugin inventory output"
	case errors.As(err, &exit) && exit.ExitCode() < 0:
		result.Reason = "wp-cli was terminated by a signal"
	default:
		text := strings.ToLower(string(out))
		if len(out) == 0 && exit != nil {
			text = strings.ToLower(string(exit.Stderr))
		}
		switch {
		case commandRefused(err) && strings.Contains(text, "error: this does not seem to be a wordpress installation."):
			result.State, result.Reason = "not_wordpress", "wp-cli did not find a WordPress installation"
		case strings.Contains(text, "fatal error"), strings.Contains(text, "parse error"):
			result.Reason = "WordPress configuration or PHP initialization failed"
		case strings.Contains(text, "checksum"):
			result.Reason = "WordPress checksum data could not be obtained or verified"
		case strings.Contains(text, "database connection"):
			result.Reason = "WordPress could not connect to its database"
		case strings.Contains(text, "permission denied"):
			result.Reason = "wp-cli could not read installation files or execute a required command"
		case strings.Contains(text, "not found"):
			result.Reason = "wp-cli or a required installation file is unavailable"
		case len(text) == 0:
			result.Reason = "wp-cli returned no diagnostic output"
		}
	}
	return result
}

// CheckWPPluginVerification reports the shared inventory independently of its
// outdated/known-vulnerable consumers. The existing plugin refresh interval and
// disabled_checks controls remain authoritative.
func CheckWPPluginVerification(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if ctx == nil {
		ctx = context.Background()
	}
	if incompleteCollectorFrom(ctx) == nil {
		ctx, _ = withIncompleteCheckCollector(ctx)
	}
	disabled := make(map[string]bool)
	if cfg != nil {
		for _, name := range cfg.DisabledChecks {
			disabled[strings.TrimSpace(name)] = true
		}
	}
	if disabled["outdated_plugins"] && (disabled["vulnerable_plugins"] || (cfg != nil && !cfg.VulnerablePluginScanningEnabled())) {
		return nil
	}
	db := store.Global()
	if db == nil {
		return nil
	}
	ensurePluginCacheFresh(ctx, cfg, db)
	var updateErr error
	if checkMarkedIncomplete(ctx, "wp_plugin_inventory") {
		updateErr = errors.New("verification history update failed")
	}
	return wpVerificationFindings(ctx, db, "plugins", "wp_plugin_inventory", updateErr)
}
