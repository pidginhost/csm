package checks

import (
	"path/filepath"
	"regexp"
	"strings"
)

// cPanel records the MultiPHP version chosen for each vhost in a fixed column
// of /etc/userdatadomains, as an "ea-phpNN" or "alt-phpNN" token.
// Anything outside that shape is not a version we can turn into a path.
var userdataPHPVersionRe = regexp.MustCompile(`^(ea|alt)-php([0-9]{2})$`)

const userdataPHPVersionField = 9

// parseVhostPHPVersion pulls the MultiPHP token out of a /etc/userdatadomains
// row. The field has a fixed position after the IPv6-dedicated flag. Older
// rows may stop before it and newer rows may carry trailing empty fields, so
// accept only the fixed PHP-version column instead of searching attacker-adjacent
// fields for a version-shaped token.
func parseVhostPHPVersion(fields []string) string {
	if len(fields) <= userdataPHPVersionField {
		return ""
	}
	for _, trailing := range fields[userdataPHPVersionField+1:] {
		if strings.TrimSpace(trailing) != "" {
			return ""
		}
	}
	tok := strings.TrimSpace(fields[userdataPHPVersionField])
	if userdataPHPVersionRe.MatchString(tok) {
		return tok
	}
	return ""
}

// phpBinForVersion maps a cPanel MultiPHP version token to its interpreter.
// EasyApache and CloudLinux alt-php lay their trees out differently, so the
// two shapes are built separately rather than by string substitution.
// Returns empty for anything that is not a well-formed version token, which is
// what keeps a malformed or attacker-influenced map out of a crontab line.
func phpBinForVersion(version string) string {
	m := userdataPHPVersionRe.FindStringSubmatch(strings.TrimSpace(version))
	if m == nil {
		return ""
	}
	if m[1] == "alt" {
		return "/opt/alt/php" + m[2] + "/usr/bin/php"
	}
	return "/opt/cpanel/ea-php" + m[2] + "/root/usr/bin/php"
}

// resolveDocrootPHPBin returns the PHP interpreter the owner's docroot is
// pinned to, or empty when the docroot is unknown, ambiguous, or unusable.
//
// WP-Cron has to run under the same interpreter as the site: a docroot pinned
// to an old MultiPHP version fatal-errors when driven by a newer system
// default, which silently kills scheduled tasks on that site.
//
// The result is deliberately restricted to the two known-good path shapes.
// safeManagedWPCronPHPBin accepts exactly those, so a resolved path never
// makes CSM report its own crontab as an unexpected change.
func resolveDocrootPHPBin(owner, docroot string) string {
	content, err := osFS.ReadFile(userdataDomainsPath)
	if err != nil {
		return ""
	}
	want := filepath.Clean(docroot)
	vhosts, _ := parseUserdataDomainRootsChecked(string(content))
	resolved := ""
	for _, vh := range vhosts {
		if vh.user != owner || vh.docroot != want {
			continue
		}
		bin := phpBinForVersion(vh.phpVersion)
		if bin == "" || !safeManagedWPCronPHPBin(bin) {
			return ""
		}
		if resolved != "" && resolved != bin {
			return ""
		}
		resolved = bin
	}
	return resolved
}

// resolveWPCronPHPBin distinguishes an operator override or unambiguous vhost
// mapping from fallback detection. Callers upgrading an existing managed line
// use that provenance to avoid replacing a known-good interpreter when the
// domain map is temporarily unavailable.
func resolveWPCronPHPBin(owner, docroot string, opts WPCronFixOptions) (string, bool) {
	if opts.PHPBin != "" {
		return opts.PHPBin, true
	}
	if bin := resolveDocrootPHPBin(owner, docroot); bin != "" {
		return bin, true
	}
	return detectPHPBin(), false
}

// wpCronPHPBin picks the interpreter for a managed cron line. An operator who
// sets php_bin has overridden the choice deliberately, so that wins; otherwise
// the vhost's own version wins; detection is the last resort so a host without
// a usable domain map still gets an installable line.
func wpCronPHPBin(owner, docroot string, opts WPCronFixOptions) string {
	bin, _ := resolveWPCronPHPBin(owner, docroot, opts)
	return bin
}
