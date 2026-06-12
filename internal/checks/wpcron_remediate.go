package checks

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
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
	// Clamped to [1,60]; a non-positive value falls back to the 15-minute default.
	IntervalMinutes int
	// PHPBin is the interpreter the cron line invokes. Empty means "detect":
	// LookPath("php") first, then the cPanel default /usr/local/bin/php.
	PHPBin string
}

const (
	wpCronDefaultIntervalMin = 15
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
var validCPUser = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

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
	if !validCPUser.MatchString(owner) || owner == "root" {
		return false, fmt.Errorf("refusing crontab edit for unexpected account name %q", owner)
	}
	if !safeWPCronDocroot(docroot) {
		return false, fmt.Errorf("refusing crontab edit for unsafe WP-Cron docroot %q", docroot)
	}
	if opts.PHPBin == "" {
		opts.PHPBin = detectPHPBin()
	}
	if !safeCronCommandString(opts.PHPBin) {
		return false, fmt.Errorf("refusing crontab edit for unsafe WP-Cron php binary %q", opts.PHPBin)
	}

	lock := wpCronCrontabLock(owner)
	lock.Lock()
	defer lock.Unlock()

	existing := ""
	if out, err := cmdExec.RunAllowNonZero("crontab", "-u", owner, "-l"); err == nil {
		existing = string(out)
	}

	want := wpCronJobLine(owner, docroot, opts)

	var buf bytes.Buffer
	switch {
	case wpCronUpgradeManagedLine(existing, docroot, want, &buf):
		// Stale CSM-managed line rewritten in place (legacy synchronized
		// schedule, changed interval, or changed php path).
	case crontabHasWPCronJob(existing, docroot):
		// Current managed line, or a customer-authored wp-cron entry CSM
		// must not fight over.
		return false, nil
	default:
		buf.WriteString(strings.TrimRight(existing, "\n"))
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString(wpCronJobMarker + docroot + "\n")
		buf.WriteString(want + "\n")
	}

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
			break
		}
	}
	for _, p := range paths {
		if p != recorded {
			forgetSelfWrites(p)
		}
	}
}

// wpCronSpoolDirs lists where cron daemons keep per-user crontabs (cronie,
// then Debian-style cron). A var so tests can point it at a temp dir.
var wpCronSpoolDirs = []string{"/var/spool/cron", "/var/spool/cron/crontabs"}

func crontabSpoolPaths(owner string) []string {
	paths := make([]string, 0, len(wpCronSpoolDirs))
	for _, dir := range wpCronSpoolDirs {
		paths = append(paths, filepath.Join(dir, owner))
	}
	return paths
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
//
// The minute field is staggered per account+docroot: a plain */N schedule is
// wall-clock aligned, so every managed site on the host fires in the same
// second and the load spikes once per interval. The offset hash is
// deterministic so reinstalls are idempotent. flock skips a run while the
// previous one still holds the lock; $HOME is expanded by crond, and the lock
// lives in the account home because /tmp is symlink-attackable.
func wpCronJobLine(owner, docroot string, opts WPCronFixOptions) string {
	interval := clampInterval(opts.IntervalMinutes)
	php := opts.PHPBin
	if php == "" {
		php = detectPHPBin()
	}
	return fmt.Sprintf(`%s * * * * cd %s && flock -n "$HOME/.csm-wpcron-%08x.lock" %s -d max_execution_time=300 wp-cron.php >/dev/null 2>&1`,
		wpCronMinuteField(wpCronStaggerOffset(owner, docroot, interval), interval),
		shellQuote(docroot), wpCronLockID(docroot), shellQuote(php))
}

// wpCronStaggerOffset spreads managed sites across the interval. Hashing
// owner+docroot (not just docroot) keeps multi-site accounts spread too.
func wpCronStaggerOffset(owner, docroot string, interval int) int {
	h := fnv.New32a()
	h.Write([]byte(owner))
	h.Write([]byte{0})
	h.Write([]byte(docroot))
	return int(h.Sum32() % uint32(interval)) // #nosec G115 -- interval clamped to [1,60]
}

func wpCronLockID(docroot string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(docroot))
	return h.Sum32()
}

func wpCronMinuteField(offset, interval int) string {
	switch {
	case interval <= 1:
		return "*"
	case interval >= 60:
		return strconv.Itoa(offset)
	case 60%interval == 0:
		return fmt.Sprintf("%d-59/%d", offset, interval)
	default:
		minutes := make([]int, 0, (60+interval-1)/interval)
		for minute := 0; minute < 60; minute += interval {
			minutes = append(minutes, (minute+offset)%60)
		}
		sort.Ints(minutes)
		parts := make([]string, 0, len(minutes))
		for _, minute := range minutes {
			parts = append(parts, strconv.Itoa(minute))
		}
		return strings.Join(parts, ",")
	}
}

// wpCronUpgradeManagedLine rewrites the job line under this docroot's CSM
// marker when it differs from want, writing the full crontab into buf. It
// returns false when there is no marker, the managed line already matches, or
// the line after the marker is not a wp-cron job for this docroot (a crontab
// the customer rearranged is left alone rather than guessed at).
func wpCronUpgradeManagedLine(existing, docroot, want string, buf *bytes.Buffer) bool {
	lines := strings.Split(existing, "\n")
	marker := wpCronJobMarker + docroot
	for i, line := range lines {
		if strings.TrimSpace(line) != marker {
			continue
		}
		if i+1 >= len(lines) {
			lines = append(lines, want)
			writeCrontabLines(buf, lines)
			return true
		}
		job := lines[i+1]
		if strings.TrimSpace(job) == "" && i+1 == len(lines)-1 {
			lines[i+1] = want
			writeCrontabLines(buf, lines)
			return true
		}
		if strings.TrimSpace(job) == want {
			return false
		}
		if cmd := crontabCommand(job); cmd == "" || !commandRunsWPCronForDocroot(cmd, docroot) {
			return false
		}
		lines[i+1] = want
		writeCrontabLines(buf, lines)
		return true
	}
	return false
}

func writeCrontabLines(buf *bytes.Buffer, lines []string) {
	buf.WriteString(strings.TrimRight(strings.Join(lines, "\n"), "\n"))
	buf.WriteByte('\n')
}

func safeWPCronDocroot(docroot string) bool {
	return docroot != "" && filepath.IsAbs(docroot) && filepath.Clean(docroot) == docroot && safeCronCommandString(docroot)
}

func safeCronCommandString(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' || s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
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
		return crontabCommandBeforeStdin(trimmed[len(fields[0]):])
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
	return crontabCommandBeforeStdin(rest)
}

func crontabCommandBeforeStdin(command string) string {
	escaped := false
	for i := 0; i < len(command); i++ {
		switch {
		case escaped:
			escaped = false
		case command[i] == '\\':
			escaped = true
		case command[i] == '%':
			return strings.TrimSpace(command[:i])
		}
	}
	return strings.TrimSpace(command)
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
