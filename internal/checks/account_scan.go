package checks

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

const accountScanMaxFilesDefault = 10000

func effectiveAccountScanMaxFiles(cfg *config.Config) int {
	if cfg == nil || cfg.Thresholds.AccountScanMaxFiles <= 0 {
		return accountScanMaxFilesDefault
	}
	return cfg.Thresholds.AccountScanMaxFiles
}

// rankPathsByMtimeDesc orders paths most-recent-first and optionally caps
// the result at maxFiles. Lexical glob order plus a downstream check timeout
// would otherwise keep cutting iteration off at the same prefix every cycle,
// hiding indicators on late-alphabet accounts.
//
// Stat failures are tolerated: the path is kept with a zero mtime so it
// sorts to the end, letting the cap chop it first when present.
// Best-effort ranking is the goal -- dropping silently here would
// reintroduce the same hidden-input bug class the helper exists to close.
// Downstream readers handle the missing-file case on their own.
//
// A canceled ctx returns nil; nil ctx is treated as Background.
// maxFiles <= 0 disables the cap; the sort still runs.
func rankPathsByMtimeDesc(ctx context.Context, paths []string, maxFiles int) []string {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil
	}
	type entry struct {
		path  string
		mtime time.Time
	}
	ranked := make([]entry, 0, len(paths))
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return nil
		}
		var mt time.Time
		if info, err := osFS.Stat(p); err == nil {
			mt = info.ModTime()
		}
		ranked = append(ranked, entry{path: p, mtime: mt})
	}
	if err := ctx.Err(); err != nil {
		return nil
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].mtime.Equal(ranked[j].mtime) {
			return ranked[i].path < ranked[j].path
		}
		return ranked[i].mtime.After(ranked[j].mtime)
	})
	if err := ctx.Err(); err != nil {
		return nil
	}
	var droppedPaths []string
	if maxFiles > 0 && len(ranked) > maxFiles {
		dropped := len(ranked) - maxFiles
		droppedPaths = make([]string, dropped)
		for i, e := range ranked[maxFiles:] {
			droppedPaths[i] = e.path
		}
		ranked = ranked[:maxFiles]
	}
	if len(droppedPaths) > 0 {
		recordAccountScanTruncatedPaths(ctx, droppedPaths, maxFiles)
	}
	out := make([]string, len(ranked))
	for i, e := range ranked {
		out[i] = e.path
	}
	return out
}

// RunAccountScan runs all applicable checks scoped to a single cPanel account.
// Returns findings for that account only. Does NOT trigger auto-response actions.
//
// This is a thin wrapper around RunAccountScanWithOptions using
// DefaultAccountScanOptions so all existing callers retain their current behaviour.
func RunAccountScan(cfg *config.Config, store *state.Store, account string) []alert.Finding {
	return RunAccountScanWithOptions(context.Background(), cfg, store, account, DefaultAccountScanOptions(cfg))
}

// RunAccountScanWithOptions is the options-aware entry point for per-account scans.
// Scope is propagated through ctx via ContextWithAccountScope, so parallel
// scans of different accounts no longer block on a single process-wide
// mutex and never bleed scope into each other.
func RunAccountScanWithOptions(ctx context.Context, cfg *config.Config, store *state.Store, account string, opts AccountScanOptions) []alert.Finding {
	// Verify account exists
	homeDir := accountHomeDir(account)
	if _, err := osFS.Stat(homeDir); os.IsNotExist(err) {
		return []alert.Finding{{
			Severity:  alert.Warning,
			Check:     "account_scan",
			Message:   fmt.Sprintf("Account '%s' not found (no %s directory)", account, homeDir),
			Timestamp: time.Now(),
		}}
	}

	// Account-scoped checks (filesystem + account-specific)
	accountChecks := []namedCheck{
		{"webshells", CheckWebshells},
		{"htaccess", CheckHtaccess},
		{"wp_core", CheckWPCore},
		{"php_content", CheckPHPContent},
		{"phishing", CheckPhishing},
		{"filesystem", CheckFilesystem},
		{"group_writable_php", CheckGroupWritablePHP},
		{"nulled_plugins", CheckNulledPlugins},
		{"open_basedir", CheckOpenBasedir},
		{"symlink_attacks", CheckSymlinkAttacks},
		{"db_content", CheckDatabaseContent},
		{"php_config_changes", CheckPHPConfigChanges},
	}

	// Account-specific checks that need the account name
	accountChecks = append(accountChecks,
		namedCheck{"ssh_keys_account", makeAccountSSHKeyCheck(account)},
		namedCheck{"crontab_account", makeAccountCrontabCheck(account)},
		namedCheck{"backdoor_binaries", makeAccountBackdoorCheck(account)},
	)

	// File-index audit: only included for full scans (ForceFileIndex=true).
	// In default scans CheckFileIndex writes live state (fileindex.current,
	// fileindex.previous, dircache.json) that the host-wide incremental
	// baseline relies on. Adding it unconditionally would corrupt that state
	// once per triggered account scan. The audit branch (ForceFileIndex=true)
	// is read-only and account-scoped so it is safe to include here.
	if opts.ForceFileIndex {
		accountChecks = append(accountChecks, namedCheck{"file_index", CheckFileIndex})
	}

	// Run under the host-wide scan budget - filesystem checks all walk the
	// same directory tree, so too many concurrent checks starve each other on
	// loaded servers with slow I/O, and a periodic tier may be running too.
	scanCtx, truncations := withAccountScanTruncationCollector(ctx)
	scanCtx = ContextWithAccountScope(scanCtx, account)
	scanCtx = ContextWithScanOptions(scanCtx, opts)
	scanCtx = withWPInstallCache(scanCtx)
	findings := runAccountChecksBounded(scanCtx, cfg, store, accountChecks)

	now := time.Now()
	findings = append(findings, truncations.findings(now)...)
	for i := range findings {
		if findings[i].Timestamp.IsZero() {
			findings[i].Timestamp = now
		}
	}

	// Filter findings to only include this account's paths
	var filtered []alert.Finding
	for _, f := range findings {
		if accountScanFindingInScope(f, account) {
			filtered = append(filtered, f)
		}
	}

	return stampTenantIDIfEmpty(filtered, account)
}

// runAccountChecksBounded runs checks under the host-wide scan budget.
// A check still waiting for a slot when ctx is cancelled never starts: the
// slot wait used to ignore the context, so an operator's cancel left every
// queued check running to its (immediate) end and reporting a timeout.
func runAccountChecksBounded(ctx context.Context, cfg *config.Config, store *state.Store, checks []namedCheck) []alert.Finding {
	scansInFlight.Add(1)
	defer scansInFlight.Add(-1)
	var mu sync.Mutex
	var findings []alert.Finding
	var wg sync.WaitGroup
	budget := scanBudgetFrom(ctx)
	dispatches := checkDispatches.begin(len(checks), budget)
	checkDispatches.observe(ctx, dispatches)

	for i, nc := range checks {
		wg.Add(1)
		c := nc
		task := dispatches[i]
		// Account checks run against user filesystem content (unparsed PHP,
		// crafted archives, foreign encodings) so a panic is plausible.
		// runAccountScanCheck surfaces it as check_panic, keeping the scan and
		// daemon alive.
		obs.SafeGo("account-scan-runner", task.wrap(func() {
			defer wg.Done()
			if !task.admit(ctx) {
				task.withdraw(ctx)
				return
			}
			if ctx.Err() != nil {
				task.withdraw(ctx)
				return
			}

			results := runAccountScanCheck(withCheckDispatch(ctx, task), c, cfg, store, timeoutFor(c.name))
			if len(results) > 0 {
				mu.Lock()
				findings = append(findings, results...)
				mu.Unlock()
			}
		}))
	}

	wg.Wait()
	return findings
}

// runAccountScanCheck runs one check under a timeout, recovering any panic.
// A check cut short because the scan itself was cancelled reports nothing:
// that is not a timeout, and the warning would be persisted with the partial
// results the cancel keeps.
func runAccountScanCheck(ctx context.Context, c namedCheck, cfg *config.Config, store *state.Store, timeout time.Duration) []alert.Finding {
	if ctx.Err() != nil {
		checkDispatchFrom(ctx).withdraw(ctx)
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	panicIdentity := alert.Finding{Check: "check_panic", DedupKey: fmt.Sprintf("account-scan:%q:%s", AccountFromContext(ctx), c.name)}

	execution := executeCheckAsync(cctx, "account-scan-exec", func() []alert.Finding {
		return c.fn(cctx, cfg, store)
	})
	defer execution.finishCaller()

	select {
	case outcome := <-execution.done:
		execution.received()
		if outcome.panicErr != "" {
			// Keep stack churn out of identity without merging failures from
			// different accounts or the scheduled runner.
			return []alert.Finding{{
				Severity:  alert.High,
				Check:     "check_panic",
				TenantID:  AccountFromContext(ctx),
				Message:   fmt.Sprintf("Account scan check '%s' stopped after an internal panic", c.name),
				Details:   outcome.panicErr,
				DedupKey:  panicIdentity.DedupKey,
				Timestamp: time.Now(),
			}}
		}
		if store != nil && cctx.Err() == nil {
			store.RearmFindings([]string{panicIdentity.Key()})
		}
		return outcome.findings
	case <-cctx.Done():
		execution.withdraw(cctx.Err())
		if ctx.Err() != nil {
			return nil
		}
		return []alert.Finding{{
			Severity:  alert.Warning,
			Check:     "check_timeout",
			Message:   fmt.Sprintf("Account scan check '%s' timed out", c.name),
			Timestamp: time.Now(),
		}}
	}
}

func accountScanFindingInScope(f alert.Finding, account string) bool {
	if account == "" {
		return true
	}
	if f.FilePath != "" {
		fileAccount := accountFromHomePath(f.FilePath)
		if fileAccount != "" {
			return fileAccount == account
		}
		if containsHomeReference(f.FilePath) {
			return false
		}
	}

	hasHomeRef, hasAccountRef := textHomeScope(f.Message, account)
	detailsHasHomeRef, detailsHasAccountRef := textHomeScope(f.Details, account)
	if hasAccountRef || detailsHasAccountRef {
		return true
	}
	if hasHomeRef || detailsHasHomeRef {
		return false
	}
	return true
}

// accountRootPrefixLen reports whether text starts with an account root
// and how long that prefix is. "/home" keeps cPanel's multi-home tolerance
// (/home2, /home3) so findings from those trees still resolve.
func accountRootPrefixLen(text string) (int, bool) {
	for _, root := range accountHomeRoots() {
		root = filepath.ToSlash(filepath.Clean(root))
		if !strings.HasPrefix(text, root) {
			continue
		}
		i := len(root)
		if root == "/home" {
			for i < len(text) && text[i] >= '0' && text[i] <= '9' {
				i++
			}
		}
		if i == len(text) || text[i] == '/' {
			return i, true
		}
	}
	return 0, false
}

func containsHomeReference(path string) bool {
	_, ok := accountRootPrefixLen(filepath.ToSlash(filepath.Clean(path)))
	return ok
}

func textHomeScope(text, account string) (hasHomeRef, hasAccountRef bool) {
	for _, root := range accountHomeRoots() {
		root = filepath.ToSlash(filepath.Clean(root))
		for i := 0; i < len(text); {
			idx := strings.Index(text[i:], root)
			if idx < 0 {
				break
			}
			start := i + idx
			if homeAccount, ok := homeAccountAt(text[start:]); ok {
				hasHomeRef = true
				if homeAccount == account {
					hasAccountRef = true
				}
			}
			i = start + len(root)
		}
	}
	return hasHomeRef, hasAccountRef
}

func homeAccountAt(text string) (string, bool) {
	i, ok := accountRootPrefixLen(text)
	if !ok {
		return "", false
	}
	if i == len(text) {
		return "", true
	}
	i++
	start := i
	for i < len(text) && isHomeAccountByte(text[i]) {
		i++
	}
	if i == start {
		return "", true
	}
	return text[start:i], true
}

func isHomeAccountByte(b byte) bool {
	return b >= 'a' && b <= 'z' ||
		b >= 'A' && b <= 'Z' ||
		b >= '0' && b <= '9' ||
		b == '_' || b == '-' || b == '.'
}

// stampTenantIDIfEmpty fills in Finding.TenantID with account when the
// detector emitted the finding without explicit tenant attribution.
// Account-scope detectors otherwise leave TenantID empty and the
// correlator falls back to weaker identities (UID, PID, file hash),
// fragmenting one account's incidents across multiple keys. Findings
// the detector did stamp keep their value; an empty account is a no-op.
func stampTenantIDIfEmpty(findings []alert.Finding, account string) []alert.Finding {
	if account == "" {
		return findings
	}
	for i := range findings {
		if findings[i].TenantID == "" {
			findings[i].TenantID = account
		}
	}
	return findings
}

// GetScanHomeDirs returns the list of home directories to scan.
// When ctx carries an account scope (via ContextWithAccountScope), only
// that account is returned. Otherwise every entry under every account root
// is read. Nil ctx is tolerated for legacy callers and treated as host-wide.
// Callers that need the directory path use scanHomeDirPath on each entry.
func GetScanHomeDirs(ctx context.Context) ([]os.DirEntry, error) {
	if account := AccountFromContext(ctx); account != "" {
		info, err := osFS.Stat(accountHomeDir(account))
		if err != nil {
			return nil, err
		}
		return []os.DirEntry{fakeDirEntry{info}}, nil
	}
	homes, err := listAccountHomes()
	if err != nil {
		return nil, err
	}
	entries := make([]os.DirEntry, 0, len(homes))
	for _, h := range homes {
		entries = append(entries, rootedDirEntry{DirEntry: h.Entry, root: h.Root})
	}
	return entries, nil
}

// rootedDirEntry remembers which account root an entry came from.
type rootedDirEntry struct {
	os.DirEntry
	root string
}

// scanHomeDirPath returns the home directory for an entry returned by
// GetScanHomeDirs (or any account enumeration): the entry's own root when it
// carries one, otherwise the root that holds the account.
func scanHomeDirPath(entry os.DirEntry) string {
	if r, ok := entry.(rootedDirEntry); ok {
		return filepath.Join(r.root, r.Name())
	}
	return accountHomeDir(entry.Name())
}

// WebRootPatterns returns the configured web-root globs, including the
// platform default when the operator did not set account_roots.
func WebRootPatterns(cfg *config.Config) []string {
	switch {
	case cfg != nil && len(cfg.AccountRoots) > 0:
		return append([]string(nil), cfg.AccountRoots...)
	case platform.Detect().IsCPanel():
		return accountHomeSubPatterns("public_html")
	default:
		return nil
	}
}

// ResolveWebRoots returns the list of directory paths CSM should scan for
// web-facing content (wp-config.php, .htaccess, public_html trees, etc.).
//
// Resolution order:
//  1. If cfg.AccountRoots is set, expand each glob and return the result.
//     Explicit config always wins.
//  2. On cPanel hosts (detected via platform.Detect), fall back to
//     /home/*/public_html for backward compatibility.
//  3. On non-cPanel hosts with no config, return an empty list. Callers
//     should treat this as "no scanning" and skip cleanly.
//
// Each returned path is an absolute directory that exists on disk.
func ResolveWebRoots(cfg *config.Config) []string {
	patterns := WebRootPatterns(cfg)

	var roots []string
	seen := make(map[string]struct{})
	for _, pattern := range patterns {
		matches, err := osFS.Glob(pattern)
		if err != nil || len(matches) == 0 {
			continue
		}
		for _, m := range matches {
			info, err := osFS.Stat(m)
			if err != nil || !info.IsDir() {
				continue
			}
			if _, ok := seen[m]; ok {
				continue
			}
			seen[m] = struct{}{}
			roots = append(roots, m)
		}
	}
	return roots
}

// fakeDirEntry wraps os.FileInfo to implement os.DirEntry.
type fakeDirEntry struct {
	fi os.FileInfo
}

func (f fakeDirEntry) Name() string               { return f.fi.Name() }
func (f fakeDirEntry) IsDir() bool                { return f.fi.IsDir() }
func (f fakeDirEntry) Type() os.FileMode          { return f.fi.Mode().Type() }
func (f fakeDirEntry) Info() (os.FileInfo, error) { return f.fi, nil }

// makeAccountSSHKeyCheck creates a check for SSH keys of a specific account.
func makeAccountSSHKeyCheck(account string) CheckFunc {
	return func(_ context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
		var findings []alert.Finding
		keyFile := filepath.Join(accountHomeDir(account), ".ssh", "authorized_keys")
		hash, err := hashFileContent(keyFile)
		if err != nil {
			return nil
		}
		key := fmt.Sprintf("_ssh_user_keys:%s", keyFile)
		prev, exists := store.GetRaw(key)
		if exists && prev != hash {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "ssh_keys",
				Message:  fmt.Sprintf("User authorized_keys modified: %s", keyFile),
			})
		}
		return findings
	}
}

// makeAccountCrontabCheck creates a check for a specific account's crontab.
func makeAccountCrontabCheck(account string) CheckFunc {
	return func(_ context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
		var findings []alert.Finding
		crontabFile := filepath.Join(cronSpoolDir(), account)
		data, err := osFS.ReadFile(crontabFile)
		if err != nil {
			return nil
		}

		content := string(data)
		for _, pattern := range MatchCrontabPatternsDeep(content, cfg) {
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "suspicious_crontab",
				Message:  fmt.Sprintf("Suspicious pattern in crontab for %s: %s", account, pattern),
				Details:  fmt.Sprintf("File: %s\nContent:\n%s", crontabFile, content),
				FilePath: crontabFile,
			})
		}
		return findings
	}
}

// makeAccountBackdoorCheck creates a check for backdoor binaries in account's .config.
func makeAccountBackdoorCheck(account string) CheckFunc {
	return func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		var findings []alert.Finding

		backdoorNames := map[string]bool{
			"defunct": true, "defunct.dat": true, "gs-netcat": true,
			"gs-sftp": true, "gs-mount": true, "gsocket": true,
		}

		patterns := []string{
			filepath.Join(accountHomeDir(account), ".config", "htop", "*"),
			filepath.Join(accountHomeDir(account), ".config", "*", "*"),
		}

		for _, pattern := range patterns {
			matches, _ := osFS.Glob(pattern)
			for _, path := range matches {
				if backdoorNames[filepath.Base(path)] {
					info, _ := osFS.Stat(path)
					var details string
					if info != nil {
						details = fmt.Sprintf("Size: %d bytes, Mtime: %s", info.Size(), info.ModTime().Format("2006-01-02 15:04:05"))
					}
					findings = append(findings, alert.Finding{
						Severity: alert.Critical,
						Check:    "backdoor_binary",
						Message:  fmt.Sprintf("Backdoor binary found: %s", path),
						Details:  details,
						FilePath: path,
					})
				}
			}
		}
		return findings
	}
}

// LookupUID returns the UID for a system account name, or -1 if not found.
func LookupUID(account string) int {
	u, err := user.Lookup(account)
	if err != nil {
		return -1
	}
	uid := 0
	fmt.Sscanf(u.Uid, "%d", &uid)
	return uid
}

// AccountHomePatterns returns the glob for every account home ("<root>/*") on
// this platform. The realtime scanner needs it to recognise an account tree
// without hardcoding /home.
func AccountHomePatterns() []string {
	return accountHomePatterns()
}
