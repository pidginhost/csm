package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

const (
	phpIniWalkMaxDepth      = -1
	phpIniMaxRootsPerUser   = 1024
	phpIniReadDirBatch      = 256
	phpIniStateFormat       = 1
	phpIniFindingCheck      = "php_config_change"
	phpIniIncompleteCheck   = "php_config_scan_incomplete"
	phpIniIncompleteDetails = "The file exceeds the PHP configuration scan limit and was not parsed."
	phpIniSpecialDetails    = "The PHP configuration path is not a regular file and was not parsed."
	phpIniStateLockShards   = 64

	// PHPConfigMaxBytes is the shared scheduled and realtime read ceiling.
	PHPConfigMaxBytes = 1 << 20
)

// Walk limits. Per-root limits bound one document root; the per-account
// limits bound the whole account. They are vars so tests can shrink them.
//
// The per-root allowance is what the account limits used to be, because a
// single shared budget meant a large first root (a vendor or node_modules tree
// is thousands of directories on its own) consumed everything and every later
// addon domain was reported unscanned without being walked.
var (
	phpIniWalkMaxDirs           = 10000
	phpIniWalkMaxEntries        = 250000
	phpIniWalkAccountMaxDirs    = 150000
	phpIniWalkAccountMaxEntries = 3000000
)

var (
	errPHPIniNonRegular = errors.New("PHP configuration is not a regular file")
	errPHPIniTooLarge   = errors.New("PHP configuration exceeds scan limit")
	phpIniStateLocks    [phpIniStateLockShards]sync.Mutex
)

type phpIniFileState struct {
	Version      int    `json:"version"`
	Hash         string `json:"hash"`
	Assessed     bool   `json:"assessed"`
	FullAnalysis bool   `json:"full_analysis,omitempty"`
}

// phpIniWalkBudget carries both the allowance for the root currently being
// walked and the running total for the account. collectPHPIniFilesWithBudget
// resets the per-root counters on entry, so roots do not starve each other.
type phpIniWalkBudget struct {
	dirs    int
	entries int

	accountDirs    int
	accountEntries int

	// maxDirs is the operator-set per-root ceiling. It rides on the budget
	// rather than on the package var so concurrent per-account scans cannot
	// overwrite each other's limit. Zero falls back to the package default.
	maxDirs    int
	maxEntries int

	// limitHit distinguishes a walk stopped by one of the configured ceilings
	// from one stopped by an unreadable directory. Both leave the scan
	// incomplete, but only the first means coverage can be bought back by
	// raising a setting, so the operator has to be told which happened.
	limitKind walkLimit
}

// walkLimit identifies the bound that stopped a walk. The two ceilings are
// raised by two different settings, so naming the wrong one sends the
// operator to a knob that cannot recover the lost coverage.
type walkLimit int

const (
	walkLimitNone walkLimit = iota
	walkLimitDirs
	walkLimitEntries
)

// phpIniIncompleteReason explains why a walk below root did not finish. A
// ceiling that stopped it is reported with the distance covered and the setting
// that raises it; anything else is left as an unreadable-entry report.
func phpIniIncompleteReason(root string, b *phpIniWalkBudget) string {
	if b == nil {
		return fmt.Sprintf("Could not finish scanning PHP configuration files below %s.", root)
	}
	switch b.limitKind {
	case walkLimitDirs:
		return fmt.Sprintf(
			"Scanning below %s stopped after %d directories, the per-root limit, so the rest was not examined for PHP configuration files. Raise thresholds.php_config_walk_max_dirs to cover the whole account.",
			root, b.dirs,
		)
	case walkLimitEntries:
		return fmt.Sprintf(
			"Scanning below %s stopped after %d entries, the per-root limit, so the rest was not examined for PHP configuration files. Raise thresholds.php_config_walk_max_entries to cover the whole account.",
			root, b.entries,
		)
	}
	return fmt.Sprintf("Could not finish scanning PHP configuration files below %s.", root)
}

// dirLimit is the per-root directory ceiling in force for this walk.
// phpIniConfiguredMaxDirs reads the operator's per-root ceiling, tolerating a
// nil config so callers that scan without one keep the built-in default.
func phpIniConfiguredMaxDirs(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	return cfg.Thresholds.PHPConfigWalkMaxDirs
}

// phpIniConfiguredMaxEntries reads the operator's per-root entry ceiling.
func phpIniConfiguredMaxEntries(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	return cfg.Thresholds.PHPConfigWalkMaxEntries
}

func (b *phpIniWalkBudget) dirLimit() int {
	if b.maxDirs > 0 {
		return b.maxDirs
	}
	return phpIniWalkMaxDirs
}

// entryLimit is the per-root entry ceiling in force for this walk.
func (b *phpIniWalkBudget) entryLimit() int {
	if b.maxEntries > 0 {
		return b.maxEntries
	}
	return phpIniWalkMaxEntries
}

func (b *phpIniWalkBudget) startRoot() {
	b.dirs = 0
	b.entries = 0
}

func (b *phpIniWalkBudget) accountExhausted() bool {
	return b.accountDirs >= phpIniWalkAccountMaxDirs || b.accountEntries >= phpIniWalkAccountMaxEntries
}

func (b *phpIniWalkBudget) addDir() {
	b.dirs++
	b.accountDirs++
}

func (b *phpIniWalkBudget) addEntry() {
	b.entries++
	b.accountEntries++
}

// CheckPHPConfigChanges monitors .user.ini and php.ini files anywhere under an
// account's document roots for settings that weaken PHP security (disable_functions
// cleared or neutralized, allow_url_include enabled, open_basedir removed). It runs
// as a deep check; the fanotify watcher also catches these writes in real-time.
func CheckPHPConfigChanges(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding
	accountScope := AccountFromContext(ctx)

	var cpanelVhosts []vhost
	vhostRootsComplete := true
	vhostMapExpected := false
	vhostData, vhostErr := osFS.ReadFile(userdataDomainsPath)
	if vhostErr == nil {
		vhostMapExpected = true
		var complete bool
		cpanelVhosts, complete = parseUserdataDomainRootsChecked(string(vhostData))
		if !complete {
			vhostRootsComplete = false
			markCheckIncomplete(ctx, "php_config_changes")
			if accountScope == "" {
				findings = append(findings, phpIniScanIncompleteFinding(
					"PHP configuration document-root map is incomplete",
					"Some cPanel domain records were malformed, so their document roots could not be scanned.",
				))
			}
		}
	} else {
		vhostRootsComplete = false
		vhostMapExpected = vhostMapFailureIsIncomplete(vhostErr)
		if vhostMapExpected {
			markCheckIncomplete(ctx, "php_config_changes")
			if accountScope == "" {
				findings = append(findings, phpIniScanIncompleteFinding(
					"PHP configuration document-root map is unavailable",
					fmt.Sprintf("Could not read %s: %v", userdataDomainsPath, vhostErr),
				))
			}
		}
	}

	homeDirs, homeErr := GetScanHomeDirs(ctx)
	var users []string
	userSet := make(map[string]struct{})
	addUser := func(user string) {
		if _, exists := userSet[user]; exists {
			return
		}
		userSet[user] = struct{}{}
		users = append(users, user)
	}
	if homeErr == nil {
		for _, homeEntry := range homeDirs {
			if homeEntry.IsDir() {
				addUser(homeEntry.Name())
			}
		}
	}
	for _, vh := range cpanelVhosts {
		if accountScope == "" || vh.user == accountScope {
			addUser(vh.user)
		}
	}
	if homeErr != nil &&
		(!errors.Is(homeErr, os.ErrNotExist) || len(users) == 0 && vhostMapExpected) {
		markCheckIncomplete(ctx, "php_config_changes")
		if accountScope == "" {
			findings = append(findings, phpIniScanIncompleteFinding(
				"PHP configuration account discovery is incomplete",
				fmt.Sprintf("Could not enumerate account home directories: %v", homeErr),
			))
		}
	}

	for _, user := range users {
		if ctx.Err() != nil {
			markCheckIncomplete(ctx, "php_config_changes")
			return findings
		}

		// Collect every .user.ini and php.ini under the account's document
		// roots. An attacker plants a php.ini (or a nested .user.ini) deep in
		// the tree -- e.g. wp-includes/assets/php.ini -- to weaken PHP, so the
		// scan cannot stop at the docroot root or watch .user.ini alone.
		var incompleteReason string
		recordIncomplete := func(reason string) {
			markCheckIncomplete(ctx, "php_config_changes")
			if incompleteReason == "" {
				incompleteReason = reason
			}
		}

		roots := []string{filepath.Join("/home", user, "public_html")}
		rootSet := map[string]struct{}{roots[0]: {}}
		addRoot := func(root string) bool {
			root = filepath.Clean(root)
			if _, duplicate := rootSet[root]; duplicate {
				return true
			}
			if len(roots) >= phpIniMaxRootsPerUser {
				recordIncomplete(fmt.Sprintf(
					"Account %s has more than %d candidate document roots.",
					user,
					phpIniMaxRootsPerUser,
				))
				return false
			}
			rootSet[root] = struct{}{}
			roots = append(roots, root)
			return true
		}

		hasAuthoritativeRoot := false
		for _, vh := range cpanelVhosts {
			if vh.user != user {
				continue
			}
			hasAuthoritativeRoot = true
			if !addRoot(vh.docroot) {
				break
			}
		}

		// Non-cPanel panels commonly keep domains below an account-owned
		// top-level directory (for example domains/<name>/public_html).
		// Preserve that layout as a fallback when no complete cPanel map is
		// available instead of narrowing the scan to public_html.
		if !hasAuthoritativeRoot || !vhostRootsComplete {
			fallbackRoots, complete, err := phpIniFallbackRoots(
				ctx,
				user,
				phpIniMaxRootsPerUser-len(roots),
				phpIniWalkMaxEntries,
			)
			if err != nil {
				recordIncomplete(fmt.Sprintf(
					"Could not enumerate fallback document roots for account %s: %v",
					user,
					err,
				))
			} else {
				if !complete {
					recordIncomplete(fmt.Sprintf(
						"Could not finish enumerating fallback document roots for account %s.",
						user,
					))
				}
				for _, root := range fallbackRoots {
					if !addRoot(root) {
						break
					}
				}
			}
		}

		var iniPaths []string
		walkBudget := &phpIniWalkBudget{
			maxDirs:    phpIniConfiguredMaxDirs(cfg),
			maxEntries: phpIniConfiguredMaxEntries(cfg),
		}
		for _, root := range roots {
			paths, complete := collectPHPIniFilesWithBudget(ctx, root, phpIniWalkMaxDepth, walkBudget)
			if !complete {
				recordIncomplete(phpIniIncompleteReason(root, walkBudget))
			}
			iniPaths = append(iniPaths, paths...)
		}

		seen := make(map[string]struct{}, len(iniPaths))
		for _, iniPath := range iniPaths {
			if ctx.Err() != nil {
				markCheckIncomplete(ctx, "php_config_changes")
				return findings
			}
			if _, duplicate := seen[iniPath]; duplicate {
				continue
			}
			seen[iniPath] = struct{}{}

			// Bound reads and reject special files before opening them. A user
			// can create a FIFO named php.ini; reading it as an ordinary file
			// would strand a scan worker after its context timed out.
			dangerous, err := readAndAssessPHPIniFile(store, iniPath)
			if err != nil {
				switch {
				case errors.Is(err, os.ErrNotExist):
					// The candidate vanished after directory enumeration. A
					// later stable scan can confirm removal; this run cannot
					// safely clear an earlier finding.
					markCheckIncomplete(ctx, "php_config_changes")
				case errors.Is(err, errPHPIniNonRegular):
					markCheckIncomplete(ctx, "php_config_changes")
					findings = append(findings, alert.Finding{
						Severity: alert.High,
						Check:    phpIniFindingCheck,
						Message:  fmt.Sprintf("Special file used as PHP configuration: %s (user: %s)", iniPath, user),
						Details:  phpIniSpecialDetails,
						FilePath: iniPath,
					})
				case errors.Is(err, errPHPIniTooLarge):
					markCheckIncomplete(ctx, "php_config_changes")
					findings = append(findings, alert.Finding{
						Severity: alert.High,
						Check:    phpIniFindingCheck,
						Message:  fmt.Sprintf("PHP configuration too large to inspect: %s (user: %s)", iniPath, user),
						Details:  phpIniIncompleteDetails,
						FilePath: iniPath,
					})
				default:
					recordIncomplete(fmt.Sprintf(
						"Could not inspect PHP configuration %s: %v",
						iniPath,
						err,
					))
				}
				continue
			}
			if len(dangerous) > 0 {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    phpIniFindingCheck,
					Message:  fmt.Sprintf("Dangerous PHP configuration: %s (user: %s)", iniPath, user),
					Details:  fmt.Sprintf("Dangerous settings:\n- %s", strings.Join(dangerous, "\n- ")),
					FilePath: iniPath,
				})
			}
		}
		if incompleteReason != "" && ctx.Err() == nil {
			findings = append(findings, phpIniScanIncompleteFinding(
				fmt.Sprintf("PHP configuration scan incomplete for user: %s", user),
				incompleteReason,
			))
		}
	}

	return findings
}

func phpIniScanIncompleteFinding(message, details string) alert.Finding {
	return alert.Finding{
		Severity: alert.Warning,
		Check:    phpIniIncompleteCheck,
		Message:  message,
		Details:  details,
	}
}

func phpIniFallbackRoots(
	ctx context.Context,
	user string,
	maxRoots int,
	maxEntries int,
) ([]string, bool, error) {
	if maxRoots <= 0 || maxEntries <= 0 {
		return nil, false, nil
	}
	home := filepath.Join("/home", user)
	var roots []string
	entriesSeen := 0
	complete, err := forEachPHPIniDirEntry(ctx, home, func(entry os.DirEntry) bool {
		entriesSeen++
		if entriesSeen > maxEntries {
			return false
		}
		name := entry.Name()
		if !entry.IsDir() ||
			name == "public_html" ||
			name == "mail" ||
			name == "etc" ||
			name == "logs" ||
			name == "ssl" ||
			name == "tmp" ||
			strings.HasPrefix(name, ".") {
			return true
		}
		if len(roots) >= maxRoots {
			return false
		}
		roots = append(roots, filepath.Join(home, name))
		return true
	})
	if err != nil {
		return roots, false, err
	}
	return roots, complete, nil
}

func readPHPIniFile(path string) ([]byte, error) {
	info, err := osFS.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errPHPIniNonRegular
	}
	if info.Size() > PHPConfigMaxBytes {
		return nil, errPHPIniTooLarge
	}

	var f *os.File
	var openErr error
	_, productionFS := osFS.(realOS)
	if productionFS {
		// A non-blocking open prevents a regular-file-to-FIFO swap from
		// stranding the worker between the Stat above and this open.
		// #nosec G304 -- read-only candidate discovered below an account web root.
		f, openErr = os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	} else {
		f, openErr = osFS.Open(path)
	}
	if openErr == nil {
		defer func() { _ = f.Close() }()
		openedInfo, statErr := f.Stat()
		if statErr != nil {
			return nil, statErr
		}
		if !openedInfo.Mode().IsRegular() {
			return nil, errPHPIniNonRegular
		}
		data, readErr := io.ReadAll(io.LimitReader(f, PHPConfigMaxBytes+1))
		if readErr != nil {
			return nil, readErr
		}
		if len(data) > PHPConfigMaxBytes {
			return nil, errPHPIniTooLarge
		}
		return data, nil
	}
	if productionFS {
		return nil, openErr
	}

	// Map-backed providers cannot return an *os.File, so their bounded test
	// data uses the ReadFile hook.
	data, readErr := osFS.ReadFile(path)
	if readErr != nil {
		return nil, readErr
	}
	if len(data) > PHPConfigMaxBytes {
		return nil, errPHPIniTooLarge
	}
	return data, nil
}

func readAndAssessPHPIniFile(store *state.Store, path string) ([]string, error) {
	// The read and state update are one critical section. Concurrent host and
	// account scans must not let an older file snapshot overwrite the state
	// recorded for a newer snapshot. Locks are sharded by path so unrelated
	// account scans can still progress in parallel.
	lock := phpIniStateLock(path)
	lock.Lock()
	defer lock.Unlock()

	data, err := readPHPIniFile(path)
	if err != nil {
		return nil, err
	}
	return assessPHPIniFile(store, path, hashBytes(data), string(data)), nil
}

func phpIniStateLock(path string) *sync.Mutex {
	var hash uint32 = 2166136261
	for i := 0; i < len(path); i++ {
		hash ^= uint32(path[i])
		hash *= 16777619
	}
	return &phpIniStateLocks[hash%phpIniStateLockShards]
}

// assessPHPIniFile stores the content hash and whether that content needs the
// full change analysis. Re-running the selected analysis for unchanged files
// keeps active findings visible and automatically applies future parser fixes.
// The caller holds the path's state lock so the state update stays ordered
// with its file snapshot.
func assessPHPIniFile(store *state.Store, path, hash, content string) []string {
	key := "_phpini:" + path
	raw, exists := store.GetRaw(key)
	previous := decodePHPIniFileState(raw)
	if exists && previous.Assessed && previous.Hash == hash {
		if previous.FullAnalysis {
			return analyzePHPINI(content)
		}
		return PHPConfigSecurityBypasses(content)
	}

	fullAnalysis := exists && previous.Hash != "" && previous.Hash != hash
	var dangerous []string
	if fullAnalysis {
		dangerous = analyzePHPINI(content)
	} else {
		// New files and legacy hash-only state are judged on the strong,
		// low-false-positive bypass signals.
		dangerous = PHPConfigSecurityBypasses(content)
	}
	next := phpIniFileState{
		Version:      phpIniStateFormat,
		Hash:         hash,
		Assessed:     true,
		FullAnalysis: fullAnalysis,
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		panic(err)
	}
	store.SetRaw(key, string(encoded))
	return append([]string(nil), dangerous...)
}

func decodePHPIniFileState(raw string) phpIniFileState {
	var decoded phpIniFileState
	if err := json.Unmarshal([]byte(raw), &decoded); err == nil &&
		decoded.Version == phpIniStateFormat && decoded.Hash != "" {
		return decoded
	}
	return phpIniFileState{Hash: raw}
}

func analyzePHPINI(content string) []string {
	var dangerous []string
	seen := make(map[string]bool)
	appendFinding := func(message string) {
		if !seen[message] {
			seen[message] = true
			dangerous = append(dangerous, message)
		}
	}

	for _, directives := range parsePHPIniDirectiveSets(content) {
		if val, ok := directives["disable_functions"]; ok {
			disabled := disabledPHPFunctions(val)
			if len(disabled) == 0 {
				appendFinding("disable_functions cleared or neutralized (all PHP functions enabled)")
			}
			for _, fn := range dangerousPHPFunctions {
				if !disabled[fn] {
					appendFinding(fmt.Sprintf("%s not in disable_functions", fn))
				}
			}
		}
		if val, ok := directives["allow_url_include"]; ok && phpIniBoolEnabled(val) {
			appendFinding("allow_url_include enabled (remote code inclusion)")
		}
		if val, ok := directives["open_basedir"]; ok && openBasedirUnrestricted(val) {
			appendFinding("open_basedir cleared or set to / (no restriction)")
		}
	}
	return dangerous
}

// collectPHPIniFilesContext walks root up to maxDepth and returns every
// .user.ini and php.ini path found. A negative maxDepth walks all depths. No
// directory is skipped by name -- attackers hide these under node_modules and
// vendor trees. Total directory and entry limits keep a user-controlled tree
// from occupying a scan worker indefinitely.
func collectPHPIniFilesContext(ctx context.Context, root string, maxDepth int) ([]string, bool) {
	return collectPHPIniFilesWithBudget(ctx, root, maxDepth, &phpIniWalkBudget{})
}

func collectPHPIniFilesWithBudget(
	ctx context.Context,
	root string,
	maxDepth int,
	budget *phpIniWalkBudget,
) ([]string, bool) {
	type pendingDir struct {
		path     string
		depth    int
		observed bool
	}

	if budget.accountExhausted() {
		budget.limitKind = walkLimitDirs
		return nil, false
	}
	budget.startRoot()
	var out []string
	queue := []pendingDir{{path: root}}
	budget.addDir()
	complete := true

	for len(queue) > 0 {
		if ctx.Err() != nil {
			return out, false
		}
		dir := queue[0]
		queue = queue[1:]
		visitComplete, err := forEachPHPIniDirEntry(ctx, dir.path, func(e os.DirEntry) bool {
			budget.addEntry()
			if budget.entries > budget.entryLimit() || budget.accountEntries > phpIniWalkAccountMaxEntries {
				budget.limitKind = walkLimitEntries
				return false
			}
			name := e.Name()
			full := filepath.Join(dir.path, name)
			if e.IsDir() {
				if maxDepth < 0 || dir.depth < maxDepth {
					if budget.dirs >= budget.dirLimit() || budget.accountDirs >= phpIniWalkAccountMaxDirs {
						complete = false
						budget.limitKind = walkLimitDirs
						return true
					}
					queue = append(queue, pendingDir{path: full, depth: dir.depth + 1, observed: true})
					budget.addDir()
				}
				return true
			}
			if name == ".user.ini" || name == "php.ini" {
				out = append(out, full)
			}
			return true
		})
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) || dir.observed {
				complete = false
			}
			continue
		}
		if !visitComplete {
			return out, false
		}
	}
	return out, complete
}

func forEachPHPIniDirEntry(
	ctx context.Context,
	path string,
	visit func(os.DirEntry) bool,
) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if _, productionFS := osFS.(realOS); !productionFS {
		entries, err := osFS.ReadDir(path)
		if err != nil {
			return false, err
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			if !visit(entry) {
				return false, nil
			}
		}
		return true, nil
	}

	// Stream directory entries in bounded batches. os.ReadDir loads the whole
	// directory, which lets one account force a large allocation before the
	// entry budget can stop the scan.
	// #nosec G304 -- directory discovered below an account web root.
	dir, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = dir.Close() }()
	info, err := dir.Stat()
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, syscall.ENOTDIR
	}
	for {
		entries, readErr := dir.ReadDir(phpIniReadDirBatch)
		for _, entry := range entries {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			if !visit(entry) {
				return false, nil
			}
		}
		switch {
		case errors.Is(readErr, io.EOF):
			return true, nil
		case readErr != nil:
			return false, readErr
		}
	}
}

// PHPConfigSecurityBypasses returns the strong, low-false-positive signals that a
// PHP ini file weakens security: disable_functions cleared or neutralized,
// allow_url_include enabled, or open_basedir removed. Used for newly-seen
// files, where the noisier per-function diffing of analyzePHPINI would flag
// benign partial disable lists.
func PHPConfigSecurityBypasses(content string) []string {
	var out []string
	var disableFunctions, allowURLInclude, openBasedir bool
	for _, directives := range parsePHPIniDirectiveSets(content) {
		if val, ok := directives["disable_functions"]; ok && DisableFunctionsNeutralized(val) {
			disableFunctions = true
		}
		if val, ok := directives["allow_url_include"]; ok && phpIniBoolEnabled(val) {
			allowURLInclude = true
		}
		if val, ok := directives["open_basedir"]; ok && openBasedirUnrestricted(val) {
			openBasedir = true
		}
	}
	if disableFunctions {
		out = append(out, "disable_functions cleared or neutralized (dangerous PHP functions enabled)")
	}
	if allowURLInclude {
		out = append(out, "allow_url_include enabled (remote code inclusion)")
	}
	if openBasedir {
		out = append(out, "open_basedir cleared (filesystem sandbox removed)")
	}
	return out
}

// PHPConfigRealtimeRootPatterns returns the startup-time path patterns used to
// admit php.ini writes into the fanotify analyzer. Explicit account_roots are
// authoritative. On cPanel, account homes are intentionally broader than the
// primary public_html root because addon domains can live anywhere below an
// account and on alternate home mounts.
func PHPConfigRealtimeRootPatterns(cfg *config.Config) []string {
	if cfg != nil && len(cfg.AccountRoots) > 0 {
		return WebRootPatterns(cfg)
	}
	if len(WebRootPatterns(cfg)) == 0 {
		return nil
	}

	patterns := []string{"/home/*"}
	seen := map[string]struct{}{patterns[0]: {}}
	data, err := osFS.ReadFile(userdataDomainsPath)
	if err != nil {
		return patterns
	}
	vhosts, _ := parseUserdataDomainRootsChecked(string(data))
	for _, vhost := range vhosts {
		pattern := phpConfigRealtimeRootPattern(vhost.user, vhost.docroot)
		if pattern == "" {
			continue
		}
		if _, exists := seen[pattern]; exists {
			continue
		}
		seen[pattern] = struct{}{}
		patterns = append(patterns, pattern)
	}
	return patterns
}

func phpConfigRealtimeRootPattern(user, docroot string) string {
	clean := filepath.Clean(docroot)
	if !filepath.IsAbs(clean) {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) >= 2 && strings.HasPrefix(parts[0], "home") && parts[1] == user {
		return filepath.Join(string(filepath.Separator), parts[0], "*")
	}
	return clean
}

var dangerousPHPFunctions = []string{
	"exec",
	"system",
	"passthru",
	"shell_exec",
	"popen",
	"proc_open",
	"pcntl_exec",
}

// DisableFunctionsNeutralized reports whether a disable_functions value fails
// to actually disable any dangerous function -- empty, "none", or set to junk
// (the `disable_functions=ByPassed By 0xNix` camouflage). A genuine hardening
// list names at least one exact dangerous function; substrings such as
// "systemd" do not disable system().
func DisableFunctionsNeutralized(val string) bool {
	return len(disabledPHPFunctions(val)) == 0
}

func disabledPHPFunctions(val string) map[string]bool {
	disabled := make(map[string]bool)
	val = strings.ToLower(normalizePHPIniValue(val))
	items := strings.FieldsFunc(val, func(r rune) bool {
		return r == ',' || r == ' '
	})
	for _, name := range items {
		for _, dangerous := range dangerousPHPFunctions {
			if name == dangerous {
				disabled[dangerous] = true
				break
			}
		}
	}
	return disabled
}

func parsePHPIniDirectiveSets(content string) []map[string]string {
	sets := []map[string]string{{}}
	sections := make(map[string]int)
	current := 0
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		line = strings.TrimPrefix(line, "\ufeff")
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			end := strings.IndexByte(line, ']')
			if end <= 1 {
				continue
			}
			section := strings.TrimSpace(line[1:end])
			upperSection := strings.ToUpper(section)
			var sectionKey string
			switch {
			case strings.HasPrefix(upperSection, "PATH="):
				sectionKey = "PATH=" + strings.TrimSpace(section[len("PATH="):])
			case strings.HasPrefix(upperSection, "HOST="):
				sectionKey = "HOST=" + strings.ToLower(strings.TrimSpace(section[len("HOST="):]))
			default:
				// Ordinary php.ini section headings are ignored by PHP and
				// return parsing to the global directive set. Only PATH and
				// HOST headings create conditional settings.
				current = 0
				continue
			}
			if index, exists := sections[sectionKey]; exists {
				current = index
			} else {
				current = len(sets)
				sections[sectionKey] = current
				sets = append(sets, make(map[string]string))
			}
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		switch key {
		case "disable_functions", "allow_url_include", "open_basedir":
			sets[current][key] = parts[1]
		}
	}
	return sets
}

func normalizePHPIniValue(value string) string {
	value, _ = normalizePHPIniValueWithExpression(value)
	return value
}

func normalizePHPIniValueWithExpression(value string) (string, bool) {
	value = strings.TrimSpace(stripPHPIniInlineComment(value))
	joined, expression := joinPHPIniQuotedFragments(value)
	return strings.TrimSpace(joined), expression
}

// joinPHPIniQuotedFragments mirrors the INI scanner's concatenation of quoted
// and unquoted fragments. For example, ex"ec",sys"tem" is the effective value
// exec,system. An unclosed quote makes PHP reject the value; return empty so
// security restrictions fail closed instead of treating the malformed token
// as an effective hardening value.
func joinPHPIniQuotedFragments(value string) (string, bool) {
	var out strings.Builder
	out.Grow(len(value))
	var quote byte
	expression := false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if quote == 0 {
			if ch == '"' || ch == '\'' {
				quote = ch
				continue
			}
			if strings.ContainsRune("|&^~!()", rune(ch)) {
				expression = true
			}
			out.WriteByte(ch)
			continue
		}
		if ch == quote {
			quote = 0
			continue
		}
		if ch == '\\' && i+1 < len(value) {
			next := value[i+1]
			if next == quote || next == '\\' {
				out.WriteByte(next)
				i++
				continue
			}
		}
		out.WriteByte(ch)
	}
	if quote != 0 {
		return "", false
	}
	return out.String(), expression
}

func stripPHPIniInlineComment(value string) string {
	var quote byte
	escaped := false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if quote != 0 {
			if quote == '"' && ch == '\\' && !escaped {
				escaped = true
				continue
			}
			if ch == quote && !escaped {
				quote = 0
			}
			escaped = false
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
			continue
		}
		if ch == ';' {
			return value[:i]
		}
	}
	return value
}

func phpIniBoolEnabled(value string) bool {
	value, expression := normalizePHPIniValueWithExpression(value)
	value = strings.ToLower(value)
	switch value {
	case "1", "on", "true", "yes":
		return true
	}
	if expression {
		evaluated, ok := parsePHPIniIntExpression(value)
		// A syntactically unusual expression is not a trustworthy disabled
		// value. Treat it as enabled rather than let unsupported constants or
		// excessive nesting bypass the security check.
		return !ok || evaluated != 0
	}
	// PHP converts the leading signed integer portion to bool: "1foo" and
	// "1e-2" are enabled, while "0.5" is not.
	i := 0
	if i < len(value) && (value[i] == '+' || value[i] == '-') {
		i++
	}
	start := i
	nonZero := false
	for i < len(value) && value[i] >= '0' && value[i] <= '9' {
		nonZero = nonZero || value[i] != '0'
		i++
	}
	return i > start && nonZero
}

const phpIniExpressionMaxDepth = 64

type phpIniIntExprParser struct {
	input         string
	pos           int
	limitExceeded bool
}

func parsePHPIniIntExpression(value string) (int64, bool) {
	p := phpIniIntExprParser{input: value}
	result, ok := p.parseBinary(0)
	if p.limitExceeded {
		return 1, true
	}
	p.skipSpace()
	return result, ok && p.pos == len(p.input)
}

func (p *phpIniIntExprParser) parseBinary(depth int) (int64, bool) {
	left, ok := p.parseUnary(depth)
	if !ok {
		return 0, false
	}
	for {
		p.skipSpace()
		if p.pos >= len(p.input) {
			return left, true
		}
		op := p.input[p.pos]
		if op != '|' && op != '&' && op != '^' {
			return left, true
		}
		p.pos++
		right, valid := p.parseUnary(depth)
		if !valid {
			return 0, false
		}
		switch op {
		case '|':
			left |= right
		case '&':
			left &= right
		case '^':
			left ^= right
		}
	}
}

func (p *phpIniIntExprParser) parseUnary(depth int) (int64, bool) {
	if depth >= phpIniExpressionMaxDepth {
		p.limitExceeded = true
		return 0, false
	}
	p.skipSpace()
	switch {
	case p.take('!'):
		value, ok := p.parseUnary(depth + 1)
		if !ok {
			return 0, false
		}
		if value == 0 {
			return 1, true
		}
		return 0, true
	case p.take('~'):
		value, ok := p.parseUnary(depth + 1)
		return ^value, ok
	case p.take('+'):
		return p.parseUnary(depth + 1)
	case p.take('-'):
		value, ok := p.parseUnary(depth + 1)
		return -value, ok
	case p.take('('):
		value, ok := p.parseBinary(depth + 1)
		p.skipSpace()
		if !ok || !p.take(')') {
			return 0, false
		}
		return value, true
	default:
		return p.parseDecimal()
	}
}

func (p *phpIniIntExprParser) parseDecimal() (int64, bool) {
	p.skipSpace()
	start := p.pos
	var value uint64
	const maxInt64 = uint64(^uint64(0) >> 1)
	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		if ch < '0' || ch > '9' {
			break
		}
		digit := uint64(ch - '0')
		if value > (maxInt64-digit)/10 {
			value = maxInt64
		} else {
			value = value*10 + digit
		}
		p.pos++
	}
	return int64(value), p.pos > start
}

func (p *phpIniIntExprParser) skipSpace() {
	for p.pos < len(p.input) {
		switch p.input[p.pos] {
		case ' ', '\t', '\r', '\n', '\v', '\f':
			p.pos++
		default:
			return
		}
	}
}

func (p *phpIniIntExprParser) take(ch byte) bool {
	if p.pos >= len(p.input) || p.input[p.pos] != ch {
		return false
	}
	p.pos++
	return true
}

func openBasedirUnrestricted(value string) bool {
	value = normalizePHPIniValue(value)
	if value == "" {
		return true
	}
	for _, dir := range strings.Split(value, string(os.PathListSeparator)) {
		if filepath.Clean(strings.TrimSpace(dir)) == string(filepath.Separator) {
			return true
		}
	}
	return false
}
