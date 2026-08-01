package checks

import (
	"path/filepath"
	"regexp"
	"strings"
)

// cPanel records the MultiPHP version chosen for each vhost in the trailing
// column of /etc/userdatadomains, as an "ea-phpNN" or "alt-phpNN" token.
// Anything outside that shape is not a version we can turn into a path.
var userdataPHPVersionRe = regexp.MustCompile(`^(ea|alt)-php([0-9]{2})$`)

// parseVhostPHPVersion pulls the MultiPHP token out of a /etc/userdatadomains
// row. It is the last column on current cPanel builds, but older rows stop
// short and some carry a trailing empty field, so scan from the right for the
// first token that actually looks like a version instead of indexing blindly.
func parseVhostPHPVersion(fields []string) string {
	for i := len(fields) - 1; i >= 5; i-- {
		tok := strings.TrimSpace(fields[i])
		if userdataPHPVersionRe.MatchString(tok) {
			return tok
		}
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

// resolveDocrootPHPBin returns the PHP interpreter the given docroot is pinned
// to, or empty when the docroot is unknown or its version is unusable.
//
// WP-Cron has to run under the same interpreter as the site: a docroot pinned
// to an old MultiPHP version fatal-errors when driven by a newer system
// default, which silently kills scheduled tasks on that site.
//
// The result is deliberately restricted to the two known-good path shapes.
// safeManagedWPCronPHPBin accepts exactly those, so a resolved path never
// makes CSM report its own crontab as an unexpected change.
func resolveDocrootPHPBin(docroot string) string {
	content, err := osFS.ReadFile(userdataDomainsPath)
	if err != nil {
		return ""
	}
	want := filepath.Clean(docroot)
	vhosts, _ := parseUserdataDomainRootsChecked(string(content))
	for _, vh := range vhosts {
		if vh.docroot != want || vh.phpVersion == "" {
			continue
		}
		if bin := phpBinForVersion(vh.phpVersion); bin != "" && safeManagedWPCronPHPBin(bin) {
			return bin
		}
	}
	return ""
}

// wpCronPHPBin picks the interpreter for a managed cron line. An operator who
// sets php_bin has overridden the choice deliberately, so that wins; otherwise
// the vhost's own version wins; detection is the last resort so a host without
// a usable domain map still gets an installable line.
func wpCronPHPBin(docroot string, opts WPCronFixOptions) string {
	if opts.PHPBin != "" {
		return opts.PHPBin
	}
	if bin := resolveDocrootPHPBin(docroot); bin != "" {
		return bin
	}
	return detectPHPBin()
}
