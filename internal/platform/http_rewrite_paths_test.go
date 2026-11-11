package platform

import "testing"

// The web server reader takes its locations from here: LiteSpeed's XML and
// the nginx root, detected or configured, with the packaged default.
func TestHTTPRewritePlatformPaths(t *testing.T) {
	if LiteSpeedConfigPath != "/usr/local/lsws/conf/httpd_config.xml" {
		t.Fatalf("LiteSpeedConfigPath = %q", LiteSpeedConfigPath)
	}
	if got := (Info{}).NginxConfigRoot(); got != "/etc/nginx" {
		t.Fatalf("default nginx root = %q", got)
	}
	if got := (Info{NginxConfigDir: "/srv/nginx"}).NginxConfigRoot(); got != "/srv/nginx" {
		t.Fatalf("configured nginx root = %q", got)
	}
}

// A cPanel path refresh cannot retain an unrelated distro root when its
// legacy alias is absent. An explicit operator root still wins afterward.
func TestHTTPRewriteCPanelRootDoesNotUseDistroTree(t *testing.T) {
	info := Info{OS: OSAlma, Panel: PanelCPanel, WebServer: WSLiteSpeed, ApacheConfigDir: "/srv/unrelated"}
	populatePaths(&info)
	if info.ApacheConfigDir != "/etc/apache2" && info.ApacheConfigDir != "/usr/local/apache/conf" {
		t.Fatalf("cPanel root = %q, want its own Apache tree", info.ApacheConfigDir)
	}
	configured := applyOverrides(info, Overrides{ApacheConfigDir: "/srv/apache"})
	if configured.ApacheConfigDir != "/srv/apache" {
		t.Fatalf("configured cPanel root = %q", configured.ApacheConfigDir)
	}
}
