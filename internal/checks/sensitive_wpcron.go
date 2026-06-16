package checks

import (
	"path/filepath"
	"regexp"
	"strings"
)

// csmManagedWPCronJobRe matches a single crontab job line exactly as
// wpCronJobLine emits it. The command shape is fixed -- run wp-cron.php under a
// per-docroot flock -- and carries no general-purpose payload, so a job line
// matching this pattern cannot be repurposed for attacker persistence. Any
// foreign command (reverse shell, curl|bash, miner) fails the match, which is
// what keeps crontabIsExclusivelyCSMWPCron from suppressing a tampered crontab.
var csmManagedWPCronJobRe = regexp.MustCompile(
	`^[0-9*/,-]+ \* \* \* \* cd '[^']*' && flock -n "\$HOME/\.csm-wpcron-[0-9a-f]{8}\.lock" '[^']*' -d max_execution_time=300 wp-cron\.php >/dev/null 2>&1$`)

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
func crontabIsExclusivelyCSMWPCron(content []byte) bool {
	sawCSMJob := false
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			// Blank lines and comments (including the "# CSM WP-Cron" marker)
			// are never executed by crond.
			continue
		}
		if name, val, ok := splitCrontabEnv(line); ok {
			if !safeCrontabEnvAssignment(name, val) {
				return false
			}
			continue
		}
		if csmManagedWPCronJobRe.MatchString(line) {
			sawCSMJob = true
			continue
		}
		return false
	}
	return sawCSMJob
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
		return value == "/root" || strings.HasPrefix(value, "/home/") || strings.HasPrefix(value, "/root/")
	default:
		return false
	}
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
	if !strings.Contains(filepath.ToSlash(path), "/var/spool/cron/") {
		return false
	}
	return crontabIsExclusivelyCSMWPCron(content)
}
