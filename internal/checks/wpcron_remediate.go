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
	"sync"
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
var wpCronDefineRe = regexp.MustCompile(`(?i)define\s*\(\s*['"]DISABLE_WP_CRON['"]\s*,\s*['"]?(true|1)['"]?\s*\)`)

// validCPUser guards the username passed to `crontab -u`. cPanel usernames are
// lowercase alnum starting with a letter; rejecting anything else keeps a
// surprising file owner from reaching the crontab argument vector.
var validCPUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var wpCronHeredocStartRe = regexp.MustCompile(`<<<['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?`)

// Crontab installs are read-modify-write; serialize each account in-process.
var wpCronCrontabLocks sync.Map

// wp-config.php edits are read-modify-write too. Deep and periodic scans can
// overlap, so serialize each config path before resolving, reading, and writing.
var wpCronConfigLocks sync.Map

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

	lockPath, err := sanitizeFixPath(path, allowedRoots)
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}
	lock := wpCronConfigLock(lockPath)
	lock.Lock()
	defer lock.Unlock()

	resolved, info, err := resolveExistingFixPath(lockPath, allowedRoots)
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
	needsDefine := !wpCronHasActiveDisableDefine(data)
	var rewritten []byte
	if needsDefine {
		var ok bool
		rewritten, ok = insertDisableWPCron(data)
		if !ok {
			return RemediationResult{Error: "could not find a safe insertion point in wp-config.php (no \"stop editing\" marker or wp-settings.php require)"}
		}
	}

	docroot := filepath.Dir(resolved)
	owner, err := wpCronOwnerName(info)
	if err != nil {
		return RemediationResult{Error: fmt.Sprintf("could not resolve account owner of wp-config.php: %v", err)}
	}

	cronInstalled, err := installUserWPCron(owner, docroot, opts)
	if err != nil {
		return RemediationResult{Error: fmt.Sprintf("system cron install failed: %v", err)}
	}

	if needsDefine {
		if werr := writeFilePreservingOwner(resolved, rewritten, info); werr != nil {
			if cronInstalled {
				return RemediationResult{Error: fmt.Sprintf("system cron installed but wp-config.php update failed: %v", werr)}
			}
			return RemediationResult{Error: werr.Error()}
		}
		actions = append(actions, "disabled WP-Cron in wp-config.php")
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

	insertAt := wpCronInsertionLine(lines)
	if insertAt < 0 {
		return nil, false
	}

	out := make([][]byte, 0, len(lines)+1)
	out = append(out, lines[:insertAt]...)
	out = append(out, defineLine)
	out = append(out, lines[insertAt:]...)
	return bytes.Join(out, []byte("\n")), true
}

func wpCronHasActiveDisableDefine(data []byte) bool {
	inBlockComment := false
	heredocLabel := ""
	for _, line := range strings.Split(string(data), "\n") {
		code := wpCronActivePHPCode(line, &inBlockComment, &heredocLabel)
		if wpCronDefineRe.MatchString(code) {
			return true
		}
	}
	return false
}

func wpCronInsertionLine(lines [][]byte) int {
	inBlockComment := false
	heredocLabel := ""
	fallback := -1
	for i, line := range lines {
		safeAtLineStart := !inBlockComment && heredocLabel == ""
		code := wpCronActivePHPCode(string(line), &inBlockComment, &heredocLabel)
		if !safeAtLineStart {
			continue
		}
		if bytes.Contains(bytes.ToLower(line), []byte(wpCronStopMarker)) {
			return i
		}
		if fallback < 0 && strings.Contains(code, "wp-settings.php") {
			fallback = i
		}
	}
	return fallback
}

func wpCronActivePHPCode(line string, inBlockComment *bool, heredocLabel *string) string {
	if *heredocLabel != "" {
		if wpCronEndsHeredoc(line, *heredocLabel) {
			*heredocLabel = ""
		}
		return ""
	}

	var out strings.Builder
	quote := byte(0)
	escaped := false
	for i := 0; i < len(line); i++ {
		if *inBlockComment {
			if i+1 < len(line) && line[i] == '*' && line[i+1] == '/' {
				*inBlockComment = false
				i++
			}
			continue
		}

		c := line[i]
		if quote != 0 {
			out.WriteByte(c)
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}

		if c == '\'' || c == '"' {
			quote = c
			out.WriteByte(c)
			continue
		}
		if i+1 < len(line) && c == '/' && line[i+1] == '*' {
			*inBlockComment = true
			i++
			continue
		}
		if i+1 < len(line) && c == '/' && line[i+1] == '/' {
			break
		}
		if c == '#' {
			break
		}
		out.WriteByte(c)
	}

	code := out.String()
	if match := wpCronHeredocStartRe.FindStringSubmatch(code); len(match) == 2 {
		*heredocLabel = match[1]
	}
	return code
}

func wpCronEndsHeredoc(line, label string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == label || trimmed == label+";"
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

	lock := wpCronCrontabLock(owner)
	lock.Lock()
	defer lock.Unlock()

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

	expected := append([]byte(nil), buf.Bytes()...)
	preRecordCrontabSelfWrite(owner, expected)
	if _, err := cmdExec.Run("crontab", "-u", owner, tmpPath); err != nil {
		forgetSelfWrites(crontabSpoolPaths(owner)...)
		return false, fmt.Errorf("crontab install: %v", err)
	}
	recordCrontabSelfWrite(owner, expected)
	return true, nil
}

func preRecordCrontabSelfWrite(owner string, expected []byte) {
	for _, p := range crontabSpoolPaths(owner) {
		RecordSelfWrite(p, expected)
	}
}

// recordCrontabSelfWrite registers the just-installed crontab with the
// self-write ledger so the sensitive-file detectors do not flag CSM's own
// change. The on-disk spool content (cron may normalize it) is what the
// detectors hash, so record the spool file rather than our staged buffer.
func recordCrontabSelfWrite(owner string, expected []byte) {
	paths := crontabSpoolPaths(owner)
	recorded := ""
	for _, p := range paths {
		data, err := osFS.ReadFile(p)
		if err != nil {
			continue
		}
		if crontabContentEqual(data, expected) {
			RecordSelfWrite(p, data)
			recorded = p
		}
		break
	}
	for _, p := range paths {
		if p != recorded {
			forgetSelfWrites(p)
		}
	}
}

func crontabSpoolPaths(owner string) []string {
	return []string{
		filepath.Join("/var/spool/cron", owner),
		filepath.Join("/var/spool/cron/crontabs", owner),
	}
}

func crontabContentEqual(got, want []byte) bool {
	got = normalizeCrontabLineEndings(got)
	want = normalizeCrontabLineEndings(want)
	if bytes.Equal(got, want) {
		return true
	}
	return bytes.HasSuffix(want, []byte("\n")) && bytes.Equal(got, bytes.TrimSuffix(want, []byte("\n")))
}

func normalizeCrontabLineEndings(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
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
		interval, shellQuote(docroot), shellQuote(php))
}

// crontabHasWPCronJob reports whether the crontab already runs wp-cron.php for
// docroot, regardless of interval or php path, so re-running the fix is a no-op.
func crontabHasWPCronJob(crontab, docroot string) bool {
	docroot = filepath.Clean(docroot)
	for _, line := range strings.Split(crontab, "\n") {
		command := crontabCommand(line)
		if command == "" {
			continue
		}
		if commandRunsWPCronForDocroot(command, docroot) {
			return true
		}
	}
	return false
}

func wpCronCrontabLock(owner string) *sync.Mutex {
	lock, _ := wpCronCrontabLocks.LoadOrStore(owner, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

func wpCronConfigLock(path string) *sync.Mutex {
	lock, _ := wpCronConfigLocks.LoadOrStore(path, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

func crontabCommand(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ""
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 || strings.Contains(fields[0], "=") {
		return ""
	}
	if strings.HasPrefix(fields[0], "@") {
		if len(fields) < 2 {
			return ""
		}
		return strings.TrimSpace(trimmed[len(fields[0]):])
	}
	if len(fields) < 6 {
		return ""
	}

	rest := trimmed
	for i := 0; i < 5; i++ {
		rest = strings.TrimLeft(rest, " \t")
		fieldEnd := strings.IndexAny(rest, " \t")
		if fieldEnd < 0 {
			return ""
		}
		rest = rest[fieldEnd:]
	}
	return strings.TrimSpace(rest)
}

func commandRunsWPCronForDocroot(command, docroot string) bool {
	if !strings.Contains(command, "wp-cron.php") {
		return false
	}
	words := shellWords(command)
	wpCronPath := filepath.Clean(filepath.Join(docroot, "wp-cron.php"))
	for _, word := range words {
		if cleanShellPathWord(word) == wpCronPath {
			return true
		}
	}
	for i, word := range words {
		if word != "cd" {
			continue
		}
		j := i + 1
		for j < len(words) && strings.HasPrefix(words[j], "-") {
			j++
		}
		if j >= len(words) || filepath.Clean(words[j]) != docroot {
			continue
		}
		for _, later := range words[j+1:] {
			if filepath.Base(cleanShellPathWord(later)) == "wp-cron.php" {
				return true
			}
		}
	}
	return false
}

func cleanShellPathWord(word string) string {
	if i := strings.IndexAny(word, "?#"); i >= 0 {
		word = word[:i]
	}
	return filepath.Clean(word)
}

func shellWords(command string) []string {
	var words []string
	var current strings.Builder
	quote := byte(0)
	escaped := false
	flush := func() {
		if current.Len() == 0 {
			return
		}
		words = append(words, current.String())
		current.Reset()
	}
	for i := 0; i < len(command); i++ {
		c := command[i]
		if quote != 0 {
			if escaped {
				current.WriteByte(c)
				escaped = false
				continue
			}
			if c == '\\' && quote == '"' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
				continue
			}
			current.WriteByte(c)
			continue
		}
		if escaped {
			current.WriteByte(c)
			escaped = false
			continue
		}
		switch c {
		case '\\':
			escaped = true
		case '\'', '"':
			quote = c
		case ' ', '\t', ';', '&', '|', '(', ')', '<', '>':
			flush()
		default:
			current.WriteByte(c)
		}
	}
	if escaped {
		current.WriteByte('\\')
	}
	flush()
	return words
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
