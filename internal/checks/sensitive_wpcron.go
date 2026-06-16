package checks

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// csmManagedWPCronJobRe matches a single crontab job line exactly as
// wpCronJobLine emits it. The command shape is fixed -- run wp-cron.php under a
// per-docroot flock -- and carries no general-purpose payload, so a job line
// matching this pattern cannot be repurposed for attacker persistence. Any
// foreign command (reverse shell, curl|bash, miner) fails the match, which is
// what keeps crontabIsExclusivelyCSMWPCron from suppressing a tampered crontab.
var csmManagedWPCronJobRe = regexp.MustCompile(
	`^([0-9*/,-]+) \* \* \* \* cd ('(?:[^']|'\\'')*') && flock -n "\$HOME/\.csm-wpcron-([0-9a-f]{8})\.lock" ('(?:[^']|'\\'')*') -d max_execution_time=300 wp-cron\.php >/dev/null 2>&1$`)

var (
	cpanelPHPBinRe     = regexp.MustCompile(`^/opt/cpanel/ea-php[0-9]{2}/root/usr/bin/php$`)
	cloudLinuxPHPBinRe = regexp.MustCompile(`^/opt/alt/php[0-9]{2}/usr/bin/php$`)
)

// safeCrontabShells is the set of SHELL values a fully CSM-managed crontab may
// carry. SHELL is honored by crond to exec every job, so an arbitrary value is
// a code-execution vector; only known shells (cPanel's jailshell and the
// standard system shells) are accepted. cPanel prepends the jailshell line to
// every user crontab it touches.
var safeCrontabShells = map[string]bool{
	"/usr/local/cpanel/bin/jailshell": true,
	"/bin/bash":                       true,
	"/bin/sh":                         true,
	"/usr/bin/bash":                   true,
	"/usr/bin/sh":                     true,
}

// crontabIsExclusivelyCSMWPCron reports whether every meaningful line in a user
// crontab is either an inert header (blank, comment, or a vetted environment
// assignment) or a CSM-installed WP-Cron job line. Such a crontab is fully
// CSM-managed; flagging it as a sensitive-file change is a false positive that
// the in-memory, TTL-bounded self-write ledger misses after a daemon restart or
// a crontab reformat by crond/cPanel.
//
// Safety: this is a content-structure recognizer, not a path allowlist. A
// single foreign cron entry, an unrecognized environment assignment (PATH,
// BASH_ENV, ...), or an unsafe SHELL value makes it return false, so attacker
// persistence layered into a crontab is still surfaced. At least one CSM job
// line is required so an all-headers crontab is not mistaken for ours.
func crontabIsExclusivelyCSMWPCron(owner string, content []byte) bool {
	sawCSMJob := false
	pendingMarker := ""
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			pendingMarker = ""
			continue
		}
		if strings.HasPrefix(line, "#") {
			// Comments are never executed by crond. The CSM marker is retained
			// only to pin the following managed job to the docroot CSM wrote.
			pendingMarker = ""
			if strings.HasPrefix(line, wpCronJobMarker) {
				pendingMarker = strings.TrimSpace(strings.TrimPrefix(line, wpCronJobMarker))
			}
			continue
		}
		if name, val, ok := splitCrontabEnv(line); ok {
			if !safeCrontabEnvAssignment(name, val) {
				return false
			}
			pendingMarker = ""
			continue
		}
		if docroot, ok := csmManagedWPCronJob(line, owner); ok && pendingMarker == docroot {
			sawCSMJob = true
			pendingMarker = ""
			continue
		}
		return false
	}
	return sawCSMJob
}

func csmManagedWPCronJob(line, owner string) (string, bool) {
	m := csmManagedWPCronJobRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	minute, lockHex := m[1], m[3]
	docroot, ok := unquoteShellSingle(m[2])
	if !ok || !safeManagedWPCronDocroot(owner, docroot) {
		return "", false
	}
	phpBin, ok := unquoteShellSingle(m[4])
	if !ok || !safeManagedWPCronPHPBin(phpBin) {
		return "", false
	}
	lockID, err := strconv.ParseUint(lockHex, 16, 32)
	if err != nil || uint32(lockID) != wpCronLockID(docroot) {
		return "", false
	}
	if !wpCronMinuteMatchesOwnerDocroot(minute, owner, docroot) {
		return "", false
	}
	return docroot, true
}

func unquoteShellSingle(q string) (string, bool) {
	if len(q) < 2 || q[0] != '\'' || q[len(q)-1] != '\'' {
		return "", false
	}
	body := q[1 : len(q)-1]
	var out strings.Builder
	for len(body) > 0 {
		i := strings.IndexByte(body, '\'')
		if i < 0 {
			out.WriteString(body)
			return out.String(), true
		}
		out.WriteString(body[:i])
		if !strings.HasPrefix(body[i:], `'\''`) {
			return "", false
		}
		out.WriteByte('\'')
		body = body[i+4:]
	}
	return out.String(), true
}

func safeManagedWPCronDocroot(owner, docroot string) bool {
	if owner == "" || !safeWPCronDocroot(docroot) {
		return false
	}
	return strings.HasPrefix(docroot, "/home/"+owner+"/")
}

func safeManagedWPCronPHPBin(path string) bool {
	if !safeCronCommandString(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	switch path {
	case "/usr/local/bin/php", "/usr/bin/php", "/bin/php":
		return true
	default:
		return cpanelPHPBinRe.MatchString(path) || cloudLinuxPHPBinRe.MatchString(path)
	}
}

func wpCronMinuteMatchesOwnerDocroot(minute, owner, docroot string) bool {
	for interval := 1; interval <= wpCronMaxIntervalMin; interval++ {
		if wpCronMinuteField(wpCronStaggerOffset(owner, docroot, interval), interval) == minute {
			return true
		}
	}
	return false
}

// splitCrontabEnv parses a crontab environment line of the form NAME=value.
// crond treats a line as an assignment (not a command) when the text left of
// the first '=' is a single bare identifier; a job line such as
// "* * * * * FOO=bar cmd" has spaces before '=' and is not an assignment. The
// value's surrounding quotes are stripped to match how cPanel writes them.
func splitCrontabEnv(line string) (name, value string, ok bool) {
	eq := strings.IndexByte(line, '=')
	if eq <= 0 {
		return "", "", false
	}
	name = line[:eq]
	if strings.ContainsAny(name, " \t") {
		return "", "", false
	}
	for i, r := range name {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return "", "", false
		}
	}
	value = strings.TrimSpace(line[eq+1:])
	value = strings.Trim(value, `"'`)
	return name, value, true
}

// safeCrontabEnvAssignment reports whether a crontab environment assignment is
// inert enough to appear in a crontab still considered fully CSM-managed.
// MAILTO is stored verbatim by crond and never executed, so any value is safe.
// SHELL and HOME influence job execution, so their values are constrained.
// Every other name (PATH, BASH_ENV, LD_*, ...) is rejected.
func safeCrontabEnvAssignment(name, value string) bool {
	switch strings.ToUpper(name) {
	case "MAILTO":
		return true
	case "SHELL":
		return safeCrontabShells[value]
	case "HOME":
		return safeCrontabHome(value)
	default:
		return false
	}
}

func safeCrontabHome(value string) bool {
	if !safeCronCommandString(value) || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return false
	}
	return value == "/root" || strings.HasPrefix(value, "/home/") || strings.HasPrefix(value, "/root/")
}

// suppressedAsManagedWPCron reports whether a sensitive-file finding for a user
// crontab should be suppressed because the crontab is exclusively a
// CSM-installed WP-Cron block. Scoped to /var/spool/cron user crontabs, the
// only place CSM installs WP-Cron jobs; system drop-ins under /etc/cron.d are
// never suppressed here.
func suppressedAsManagedWPCron(path string, content []byte) bool {
	if len(content) == 0 {
		return false
	}
	owner, ok := cronSpoolOwner(path)
	if !ok {
		return false
	}
	return crontabIsExclusivelyCSMWPCron(owner, content)
}

func cronSpoolOwner(path string) (string, bool) {
	clean := filepath.ToSlash(filepath.Clean(path))
	if filepath.ToSlash(filepath.Dir(clean)) != "/var/spool/cron" {
		return "", false
	}
	owner := filepath.Base(clean)
	if owner == "." || owner == "/" || owner == "" {
		return "", false
	}
	if owner == "root" || !validCPUser.MatchString(owner) {
		return "", false
	}
	return owner, true
}
