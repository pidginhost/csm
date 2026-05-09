package modsec

import "github.com/pidginhost/csm/internal/platform"

// RuleDirs returns the candidate directories where vendor ModSecurity rules
// live for the detected web server / panel combination. The list is ordered
// from most-specific to least-specific so callers walking the dirs encounter
// the operator's installed pack before any system fallback.
func RuleDirs(info platform.Info) []string {
	var dirs []string
	switch info.WebServer {
	case platform.WSApache:
		if info.IsDebianFamily() {
			dirs = append(dirs,
				"/etc/apache2/conf.d/modsec_vendor_configs/",
				"/etc/modsecurity/",
				"/usr/share/modsecurity-crs/rules/",
			)
		}
		if info.IsRHELFamily() {
			dirs = append(dirs,
				"/etc/httpd/modsecurity.d/",
				"/etc/httpd/modsecurity.d/activated_rules/",
				"/usr/share/modsecurity-crs/rules/",
			)
		}
		dirs = append(dirs, "/usr/local/apache/conf/modsec_vendor_configs/")
	case platform.WSNginx:
		dirs = append(dirs,
			"/etc/nginx/modsec/",
			"/etc/modsecurity/",
			"/usr/share/modsecurity-crs/rules/",
		)
	}
	// cPanel + LiteSpeed: cPanel's modsec_assemble job writes vendor rules
	// into the apache2 tree even when the front-end is LiteSpeed. Without
	// this branch the rule probe has no filesystem evidence during the
	// window in which modsec_assemble itself is rewriting the tree.
	if info.IsCPanel() && info.WebServer == platform.WSLiteSpeed {
		dirs = append(dirs,
			"/etc/apache2/conf.d/modsec_vendor_configs/",
			"/usr/local/apache/conf/modsec_vendor_configs/",
		)
	}
	return dirs
}
