package checks

import (
	"errors"
	"io/fs"
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
	if tok, ok := vhostPHPColumn(fields); ok && userdataPHPVersionRe.MatchString(tok) {
		return tok
	}
	return ""
}

// vhostPHPInherits reports a vhost with no MultiPHP selection of its own.
// cPanel leaves the column empty or writes "inherit"; any other token that is
// not a version is malformed, not an inheritance.
func vhostPHPInherits(fields []string) bool {
	tok, ok := vhostPHPColumn(fields)
	return ok && (tok == "" || tok == "inherit")
}

func vhostPHPColumn(fields []string) (string, bool) {
	if len(fields) <= userdataPHPVersionField {
		return "", false
	}
	for _, trailing := range fields[userdataPHPVersionField+1:] {
		if strings.TrimSpace(trailing) != "" {
			return "", false
		}
	}
	return strings.TrimSpace(fields[userdataPHPVersionField]), true
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

	// Match the most specific docroot this account owns that serves the target.
	// A WordPress install in a subdirectory is not its own vhost, so the map has
	// no entry for it, but cPanel serves it under the enclosing vhost and hence
	// that vhost's PHP version. An exact entry always wins, because a subdomain
	// docroot can be nested inside the main one.
	version, inherit, bestLen := "", false, -1
	for _, vh := range vhosts {
		if vh.user != owner || !wpCronDocrootCovers(vh.docroot, want) {
			continue
		}
		switch {
		case len(vh.docroot) > bestLen:
			version, inherit, bestLen = vh.phpVersion, vh.phpInherit, len(vh.docroot)
		case len(vh.docroot) == bestLen && (vh.phpVersion != version || vh.phpInherit != inherit):
			// Two vhosts claim the same docroot with different selections;
			// picking either would pin the wrong interpreter.
			version, inherit = "", false
		}
	}
	if inherit {
		return inheritedHandlerPHPBin(owner, want)
	}
	if version == "" {
		return ""
	}
	bin := phpBinForVersion(version)
	if bin == "" || !safeManagedWPCronPHPBin(bin) {
		return ""
	}
	return bin
}

// inheritedHandlerPHPBin resolves the interpreter of a vhost with no MultiPHP
// selection of its own. The web server does not fall back to the system
// default there: it applies the nearest cPanel handler block in the .htaccess
// chain, which a copied, restored, or migrated docroot can still carry.
// cPanel's CLI wrapper reads only the domain map, so it disagrees with the site
// in exactly that case. The walk stays inside the owner's home: nothing above
// it is the tenant's to configure.
func inheritedHandlerPHPBin(owner, dir string) string {
	home := defaultUIDCache.HomeDir(owner)
	if home == "" {
		return ""
	}
	home = filepath.Clean(home)
	if dir != home && !strings.HasPrefix(dir, home+string(filepath.Separator)) {
		return ""
	}
	for d := dir; ; d = filepath.Dir(d) {
		data, ok, err := readTenantHtaccessBounded(home, d)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil || !ok:
			// A nearer file that cannot be read may override any ancestor.
			return ""
		default:
			if version, found := cpanelHandlerVersion(string(data)); found {
				bin := phpBinForVersion(version)
				if bin == "" || !safeManagedWPCronPHPBin(bin) || !wpCronPHPBinInstalled(bin) {
					return ""
				}
				return bin
			}
		}
		if d == home {
			return ""
		}
	}
}

// wpCronPHPBinInstalled reports whether an interpreter is present and
// executable. A handler can outlive the PHP version it names; a cron line on a
// missing binary would fail every run.
var wpCronPHPBinInstalled = func(bin string) bool {
	info, err := osFS.Stat(bin)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

const (
	cpanelHandlerBegin = "# php -- BEGIN cPanel-generated handler, do not edit"
	cpanelHandlerEnd   = "# php -- END cPanel-generated handler, do not edit"
)

var (
	htaccessAddHandlerRe = regexp.MustCompile(`^AddHandler\s+(\S+)((?:\s+\S+)+)$`)
	cpanelPHPHandlerRe   = regexp.MustCompile(`^application/x-httpd-((?:ea|alt)-php[0-9]{2})(?:___lsphp)?$`)
)

// cpanelHandlerVersion returns the PHP version the cPanel-generated handler
// blocks of one .htaccess select for .php, and whether a complete block sets
// a handler for .php. The last AddHandler for .php wins, as it does in the
// web server; an unrecognised handler selects no usable version. Directives
// outside a complete block are not cPanel's selection and are ignored.
func cpanelHandlerVersion(content string) (version string, found bool) {
	inBlock, blockVersion, blockSets := false, "", false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == cpanelHandlerBegin:
			inBlock, blockVersion, blockSets = true, "", false
		case line == cpanelHandlerEnd:
			if inBlock && blockSets {
				version, found = blockVersion, true
			}
			inBlock = false
		case inBlock:
			m := htaccessAddHandlerRe.FindStringSubmatch(line)
			if m == nil || !handlerCoversDotPHP(m[2]) {
				continue
			}
			blockVersion, blockSets = "", true
			if h := cpanelPHPHandlerRe.FindStringSubmatch(m[1]); h != nil {
				blockVersion = h[1]
			}
		}
	}
	return version, found
}

func handlerCoversDotPHP(extensions string) bool {
	for _, ext := range strings.Fields(extensions) {
		if strings.EqualFold(ext, ".php") {
			return true
		}
	}
	return false
}

// wpCronDocrootCovers reports whether vhostRoot serves docroot: either the same
// path or an ancestor of it. Comparison is path-segment aware so
// /home/a/public_html never covers /home/a/public_html_old, and a root shallower
// than /home/<user>/<dir> is rejected so inheritance cannot cross accounts.
func wpCronDocrootCovers(vhostRoot, docroot string) bool {
	vhostRoot = filepath.Clean(vhostRoot)
	if strings.Count(strings.TrimSuffix(vhostRoot, "/"), "/") < 3 {
		return false
	}
	if vhostRoot == docroot {
		return true
	}
	return strings.HasPrefix(docroot, vhostRoot+"/")
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
