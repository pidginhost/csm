package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SeccompDropInBaseName is the file name CSM writes inside each unit's
// /etc/systemd/system/<unit>.d/ override directory. Stable so the
// hardening audit can scan for it and the remove path can clean up
// without guessing.
const SeccompDropInBaseName = "csm-copy-fail-seccomp.conf"

// seccompDropInContent is the byte-exact body of every drop-in CSM
// writes. The marker comment lets a curious sysadmin understand who
// manages the file without consulting external docs.
const seccompDropInContent = `# CSM Copy Fail (CVE-2026-31431) seccomp mitigation - managed by CSM.
# Blocks socket(AF_ALG, ...) for processes spawned by this unit.
# Remove this file to disable.
[Service]
RestrictAddressFamilies=~AF_ALG
`

// afAlgSeccompCandidateUnits is the catalog of systemd units that, on
// shared-hosting servers, regularly spawn untrusted user-level code
// and therefore need the AF_ALG block. Units that do not exist on the
// running host are filtered out at apply time.
//
// The list is intentionally inclusive: a unit that does not exist
// adds zero overhead because we filter via systemctl list-unit-files
// before writing anything.
var afAlgSeccompCandidateUnits = []string{
	// Web servers
	"lshttpd.service", // LiteSpeed (cPanel default)
	"httpd.service",   // Apache (RHEL family, cPanel EA4 fallback)
	"apache2.service", // Apache (Debian/Ubuntu)
	"nginx.service",   // Nginx
	// PHP-FPM, cPanel EA4
	"ea-php72-php-fpm.service",
	"ea-php73-php-fpm.service",
	"ea-php74-php-fpm.service",
	"ea-php80-php-fpm.service",
	"ea-php81-php-fpm.service",
	"ea-php82-php-fpm.service",
	"ea-php83-php-fpm.service",
	"ea-php84-php-fpm.service",
	"cpanel_php_fpm.service",
	// PHP-FPM, generic distro versions
	"php-fpm.service",
	"php7.4-fpm.service",
	"php8.0-fpm.service",
	"php8.1-fpm.service",
	"php8.2-fpm.service",
	"php8.3-fpm.service",
	"php8.4-fpm.service",
	// Cron and mail (drop privileges to user before running content
	// filters or scheduled scripts)
	"crond.service",
	"cron.service",
	"exim.service",
	"dovecot.service",
}

// SeccompUnitState describes one unit's mitigation status in operator
// terms. Returned by ScanAFAlgSeccompState so both the CLI and the
// hardening audit can render the same view without re-deriving it.
type SeccompUnitState struct {
	Unit    string // e.g. "lshttpd.service"
	Exists  bool   // unit is registered with systemd on this host
	HasFile bool   // CSM-managed drop-in is present on disk
}

// ScanAFAlgSeccompState walks the candidate unit list and returns one
// SeccompUnitState per candidate. Units missing from systemd are still
// reported (Exists=false) so the operator can confirm CSM did not
// silently skip something they expected.
func ScanAFAlgSeccompState() []SeccompUnitState {
	var out []SeccompUnitState
	for _, u := range afAlgSeccompCandidateUnits {
		s := SeccompUnitState{Unit: u}
		s.Exists = systemdUnitExists(u)
		s.HasFile = seccompDropInPresent(u)
		out = append(out, s)
	}
	return out
}

// SeccompCoverageSummary collapses the per-unit scan into the two
// numbers an operator cares about: how many existing units have the
// CSM drop-in, and how many do not.
type SeccompCoverageSummary struct {
	Covered      []string // existing units with the CSM drop-in
	Uncovered    []string // existing units without the drop-in
	NotInstalled []string // candidate units not registered with systemd
}

// SummarizeAFAlgSeccompCoverage rolls up ScanAFAlgSeccompState into
// the three-way summary above. Used by the hardening audit and the
// CLI status output.
func SummarizeAFAlgSeccompCoverage() SeccompCoverageSummary {
	var s SeccompCoverageSummary
	for _, u := range ScanAFAlgSeccompState() {
		switch {
		case !u.Exists:
			s.NotInstalled = append(s.NotInstalled, u.Unit)
		case u.HasFile:
			s.Covered = append(s.Covered, u.Unit)
		default:
			s.Uncovered = append(s.Uncovered, u.Unit)
		}
	}
	return s
}

// ApplyAFAlgSeccompDropIns writes the canonical drop-in file for every
// candidate unit that exists on this host AND does not already have
// the file. After all writes, runs systemctl daemon-reload and a
// reload-or-restart per touched unit so the seccomp filter takes
// effect immediately.
//
// Returns the list of units that received a new drop-in this call. An
// empty list with a nil error means everything was already covered
// (idempotent re-run).
func ApplyAFAlgSeccompDropIns() ([]string, error) {
	var written []string
	for _, u := range afAlgSeccompCandidateUnits {
		if !systemdUnitExists(u) {
			continue
		}
		if seccompDropInPresent(u) {
			continue
		}
		if err := writeSeccompDropIn(u); err != nil {
			return written, fmt.Errorf("write drop-in for %s: %w", u, err)
		}
		written = append(written, u)
	}

	if len(written) == 0 {
		return nil, nil
	}

	if _, err := cmdExec.Run("systemctl", "daemon-reload"); err != nil {
		return written, fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	for _, u := range written {
		// reload-or-restart picks the lightest restart that activates
		// the new seccomp filter; PHP-FPM and LiteSpeed both support
		// graceful reload, but daemon-reload alone does NOT re-arm
		// the seccomp filter on already-running workers.
		if _, err := cmdExec.RunAllowNonZero("systemctl", "reload-or-restart", u); err != nil {
			return written, fmt.Errorf("systemctl reload-or-restart %s: %w", u, err)
		}
	}
	return written, nil
}

// RemoveAFAlgSeccompDropIns deletes every CSM-managed seccomp drop-in
// found on disk and runs systemctl daemon-reload + reload-or-restart
// per touched unit so the seccomp filter is dropped from running
// processes. Idempotent: a unit without our drop-in is skipped.
//
// Returns the list of units whose drop-in was removed.
func RemoveAFAlgSeccompDropIns() ([]string, error) {
	var removed []string
	for _, u := range afAlgSeccompCandidateUnits {
		if !seccompDropInPresent(u) {
			continue
		}
		if err := osFS.Remove(seccompDropInPath(u)); err != nil && !os.IsNotExist(err) {
			return removed, fmt.Errorf("remove drop-in for %s: %w", u, err)
		}
		// Best-effort: clean up the now-empty .d directory if we created it.
		dir := seccompDropInDir(u)
		_ = osFS.Remove(dir) // succeeds only if empty; harmless otherwise
		removed = append(removed, u)
	}

	if len(removed) == 0 {
		return nil, nil
	}

	if _, err := cmdExec.Run("systemctl", "daemon-reload"); err != nil {
		return removed, fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	for _, u := range removed {
		if !systemdUnitExists(u) {
			continue
		}
		if _, err := cmdExec.RunAllowNonZero("systemctl", "reload-or-restart", u); err != nil {
			return removed, fmt.Errorf("systemctl reload-or-restart %s: %w", u, err)
		}
	}
	return removed, nil
}

// seccompDropInDir returns the override directory for the given unit:
// /etc/systemd/system/<unit>.d
func seccompDropInDir(unit string) string {
	return filepath.Join("/etc/systemd/system", unit+".d")
}

// seccompDropInPath returns the full path to the CSM-managed drop-in
// file for the given unit.
func seccompDropInPath(unit string) string {
	return filepath.Join(seccompDropInDir(unit), SeccompDropInBaseName)
}

// seccompDropInPresent reports whether the CSM-managed drop-in exists
// for the given unit. Content is not inspected here; the file's
// presence at the canonical path is the policy signal.
func seccompDropInPresent(unit string) bool {
	_, err := osFS.Stat(seccompDropInPath(unit))
	return err == nil
}

// writeSeccompDropIn creates the override directory and writes the
// canonical drop-in content. Errors propagate to the caller.
func writeSeccompDropIn(unit string) error {
	dir := seccompDropInDir(unit)
	if err := osFS.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return osFS.WriteFile(seccompDropInPath(unit), []byte(seccompDropInContent), 0o644)
}

// systemdUnitExists asks systemctl whether the given unit is known to
// the running systemd. Returns false on any error, including missing
// systemctl binary, so a non-systemd host (rare on RHEL/Ubuntu) is
// treated as "no units to mitigate."
func systemdUnitExists(unit string) bool {
	out, err := cmdExec.RunAllowNonZero(
		"systemctl", "list-unit-files", unit, "--no-legend", "--no-pager",
	)
	if err != nil {
		return false
	}
	// list-unit-files prints a row per match. An empty stdout means
	// the unit name is not registered with this systemd instance.
	return len(strings.TrimSpace(string(out))) > 0
}
