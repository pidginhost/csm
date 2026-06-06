package checks

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// WPCronFixOptions carries operator-tunable parameters for the WP-Cron
// remediation. Both the Web UI handler and the daemon auto-response resolve
// these from config before calling the fix, so the remediation core itself
// stays free of config coupling.
type WPCronFixOptions struct {
	// IntervalMinutes is how often the installed system cron runs wp-cron.php.
	// Clamped to [1,60]; a non-positive value falls back to the 5-minute default.
	IntervalMinutes int
	// PHPBin is the interpreter the cron line invokes. Empty means "detect":
	// LookPath("php") first, then the cPanel default /usr/local/bin/php.
	PHPBin string
}

const (
	wpCronDefaultIntervalMin = 5
	wpCronMaxIntervalMin     = 60
	// wpCronEditMarker tags the line CSM inserts so the customer can see why
	// WP-Cron was disabled and so re-running the fix stays idempotent.
	wpCronEditMarker = "// CSM: WP-Cron disabled, served by system cron instead"
	// wpCronJobMarker prefixes the managed crontab block for a given docroot.
	wpCronJobMarker  = "# CSM WP-Cron "
	wpCronStopMarker = "stop editing"
)

// wpCronDefineRe matches a define of DISABLE_WP_CRON set to a truthy value,
// matching the detector's view of "already disabled".
var wpCronDefineRe = regexp.MustCompile(`(?i)define\s*\(\s*['"]DISABLE_WP_CRON['"]\s*,\s*(true|1)\s*\)`)

// validCPUser guards the username passed to `crontab -u`. cPanel usernames are
// lowercase alnum starting with a letter; rejecting anything else keeps a
// surprising file owner from reaching the crontab argument vector.
var validCPUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// wpCronOwnerName resolves the account that owns a wp-config.php. It is a var
// so tests can inject a deterministic owner regardless of who runs `go test`.
var wpCronOwnerName = fileOwnerName

// FixDisableWPCron disables WP-Cron in a wp-config.php and installs a real
// per-user system cron that runs wp-cron.php on a fixed interval. It scopes
// writes to the default per-account roots (/home).
func FixDisableWPCron(path string, opts WPCronFixOptions) RemediationResult {
	return FixDisableWPCronInRoots(path, fixPerfAllowedRoots, opts)
}

// FixDisableWPCronInRoots is FixDisableWPCron with caller-supplied roots so the
// Web UI can honor configured account_roots and tests can write under t.TempDir().
func FixDisableWPCronInRoots(path string, allowedRoots []string, opts WPCronFixOptions) RemediationResult {
	if path == "" {
		return RemediationResult{Error: "could not extract file path from finding"}
	}

	resolved, info, err := resolveExistingFixPath(path, allowedRoots)
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}
	if info.IsDir() {
		return RemediationResult{Error: "refusing to edit a directory"}
	}
	if filepath.Base(resolved) != "wp-config.php" {
		return RemediationResult{Error: fmt.Sprintf("automated WP-Cron fix only applies to wp-config.php (got %s)", filepath.Base(resolved))}
	}

	data, err := readFilePreservingIdentity(resolved, info)
	if err != nil {
		return RemediationResult{Error: fmt.Sprintf("read failed: %v", err)}
	}

	var actions []string
	fileEdited := false
	if !wpCronDefineRe.Match(data) {
		rewritten, ok := insertDisableWPCron(data)
		if !ok {
			return RemediationResult{Error: "could not find a safe insertion point in wp-config.php (no \"stop editing\" marker or wp-settings.php require)"}
		}
		if werr := writeFilePreservingOwner(resolved, rewritten, info); werr != nil {
			return RemediationResult{Error: werr.Error()}
		}
		fileEdited = true
		actions = append(actions, "disabled WP-Cron in wp-config.php")
	}

	docroot := filepath.Dir(resolved)
	owner, err := wpCronOwnerName(info)
	if err != nil {
		return RemediationResult{Error: fmt.Sprintf("could not resolve account owner of wp-config.php: %v", err)}
	}

	cronInstalled, err := installUserWPCron(owner, docroot, opts)
	if err != nil {
		// The file edit (if any) already succeeded; report partial progress so
		// the operator knows the cron still needs attention.
		msg := fmt.Sprintf("WP-Cron disabled but system cron install failed: %v", err)
		if !fileEdited {
			msg = fmt.Sprintf("system cron install failed: %v", err)
		}
		return RemediationResult{Error: msg}
	}
	if cronInstalled {
		actions = append(actions, fmt.Sprintf("installed every-%d-minute system cron for %s", clampInterval(opts.IntervalMinutes), owner))
	}

	if len(actions) == 0 {
		return RemediationResult{
			Success:     true,
			Action:      fmt.Sprintf("wp-cron already configured for %s", docroot),
			Description: "WP-Cron already disabled and system cron already present; no change needed",
		}
	}

	return RemediationResult{
		Success:     true,
		Action:      fmt.Sprintf("disable WP-Cron + install system cron for %s", docroot),
		Description: strings.Join(actions, "; "),
	}
}

// insertDisableWPCron returns wp-config.php bytes with the DISABLE_WP_CRON
// define inserted before the "stop editing" marker, or before the
// wp-settings.php require as a fallback. The second return is false when no
// safe insertion point exists, so the caller can refuse rather than append a
// define into an unfamiliar PHP file.
func insertDisableWPCron(data []byte) ([]byte, bool) {
	lines := bytes.Split(data, []byte("\n"))
	defineLine := []byte("define( 'DISABLE_WP_CRON', true ); " + wpCronEditMarker)

	insertAt := -1
	for i, line := range lines {
		if bytes.Contains(bytes.ToLower(line), []byte(wpCronStopMarker)) {
			insertAt = i
			break
		}
	}
	if insertAt < 0 {
		for i, line := range lines {
			if bytes.Contains(line, []byte("wp-settings.php")) {
				insertAt = i
				break
			}
		}
	}
	if insertAt < 0 {
		return nil, false
	}

	out := make([][]byte, 0, len(lines)+1)
	out = append(out, lines[:insertAt]...)
	out = append(out, defineLine)
	out = append(out, lines[insertAt:]...)
	return bytes.Join(out, []byte("\n")), true
}

// installUserWPCron ensures the owner's crontab contains a CSM-managed line
// running wp-cron.php for docroot. It returns false (no error) when the line
// is already present. The crontab is rewritten via a spool file because the
// command runner has no stdin channel; `crontab -u <user> <file>` installs and
// validates it atomically.
func installUserWPCron(owner, docroot string, opts WPCronFixOptions) (bool, error) {
	if !validCPUser.MatchString(owner) {
		return false, fmt.Errorf("refusing crontab edit for unexpected account name %q", owner)
	}

	existing := ""
	if out, err := cmdExec.RunAllowNonZero("crontab", "-u", owner, "-l"); err == nil {
		existing = string(out)
	}

	want := wpCronJobLine(docroot, opts)
	if crontabHasWPCronJob(existing, docroot) {
		return false, nil
	}

	var buf bytes.Buffer
	buf.WriteString(strings.TrimRight(existing, "\n"))
	if buf.Len() > 0 {
		buf.WriteByte('\n')
	}
	buf.WriteString(wpCronJobMarker + docroot + "\n")
	buf.WriteString(want + "\n")

	tmp, err := os.CreateTemp("", "csm-wpcron-*")
	if err != nil {
		return false, fmt.Errorf("create crontab spool: %v", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("write crontab spool: %v", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close crontab spool: %v", err)
	}

	if _, err := cmdExec.Run("crontab", "-u", owner, tmpPath); err != nil {
		return false, fmt.Errorf("crontab install: %v", err)
	}
	return true, nil
}

// wpCronJobLine builds the crontab entry. CLI php is used (not an HTTP hit) so
// the job does not tie up a web worker, which is the load source the finding
// flags. max_execution_time caps a runaway cron pass.
func wpCronJobLine(docroot string, opts WPCronFixOptions) string {
	interval := clampInterval(opts.IntervalMinutes)
	php := opts.PHPBin
	if php == "" {
		php = detectPHPBin()
	}
	return fmt.Sprintf("*/%d * * * * cd %s && %s -d max_execution_time=300 wp-cron.php >/dev/null 2>&1",
		interval, docroot, php)
}

// crontabHasWPCronJob reports whether the crontab already runs wp-cron.php for
// docroot, regardless of interval or php path, so re-running the fix is a no-op.
func crontabHasWPCronJob(crontab, docroot string) bool {
	for _, line := range strings.Split(crontab, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "cd "+docroot+" &&") && strings.Contains(trimmed, "wp-cron.php") {
			return true
		}
	}
	return false
}

func clampInterval(minutes int) int {
	if minutes <= 0 {
		return wpCronDefaultIntervalMin
	}
	if minutes > wpCronMaxIntervalMin {
		return wpCronMaxIntervalMin
	}
	return minutes
}

func detectPHPBin() string {
	if p, err := cmdExec.LookPath("php"); err == nil && p != "" {
		return p
	}
	return "/usr/local/bin/php"
}

// fileOwnerName resolves the username that owns the wp-config.php so the cron
// runs as the account, not root. The owner is the source of truth for which
// account this WordPress install belongs to.
func fileOwnerName(info os.FileInfo) (string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("unsupported file info")
	}
	if stat.Uid == 0 {
		// A customer wp-config.php should never be root-owned; installing a
		// cron that runs wp-cron.php as root would be a privilege smell.
		return "", fmt.Errorf("refusing to install a root-owned cron for wp-config.php")
	}
	uid := strconv.FormatUint(uint64(stat.Uid), 10)
	u, err := user.LookupId(uid)
	if err != nil {
		return "", fmt.Errorf("uid %s: %v", uid, err)
	}
	return u.Username, nil
}
