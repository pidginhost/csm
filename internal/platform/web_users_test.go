package platform

import (
	"slices"
	"testing"
)

// Checks that reason about "the web server's user" hardcoded cPanel's
// nobody. On Plesk or a panel-less Debian host the process runs as
// www-data (apache/nginx on RHEL), so the nobody-crontab audit and the
// group-writable PHP scan were looking at the wrong identity.
func TestWebServerUsers(t *testing.T) {
	cases := []struct {
		name string
		info Info
		want []string
	}{
		{"cpanel", Info{Panel: PanelCPanel, OS: OSAlma, WebServer: WSApache}, []string{"nobody"}},
		{"cpanel litespeed", Info{Panel: PanelCPanel, OS: OSAlma, WebServer: WSLiteSpeed}, []string{"nobody"}},
		{"directadmin", Info{Panel: PanelDA, OS: OSAlma, WebServer: WSApache}, []string{"apache", "nobody"}},
		{"plesk ubuntu", Info{Panel: PanelPlesk, OS: OSUbuntu, WebServer: WSApache}, []string{"www-data"}},
		{"plesk almalinux", Info{Panel: PanelPlesk, OS: OSAlma, WebServer: WSApache}, []string{"apache"}},
		{"none debian nginx", Info{Panel: PanelNone, OS: OSDebian, WebServer: WSNginx}, []string{"www-data"}},
		{"none rhel nginx", Info{Panel: PanelNone, OS: OSRocky, WebServer: WSNginx}, []string{"nginx"}},
		{"none rhel apache", Info{Panel: PanelNone, OS: OSRocky, WebServer: WSApache}, []string{"apache"}},
		{"none litespeed", Info{Panel: PanelNone, OS: OSUbuntu, WebServer: WSLiteSpeed}, []string{"nobody"}},
		{"none unknown server debian", Info{Panel: PanelNone, OS: OSUbuntu, WebServer: WSNone}, []string{"www-data"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.info.WebServerUsers(); !slices.Equal(got, tc.want) {
				t.Fatalf("WebServerUsers() = %v, want %v", got, tc.want)
			}
		})
	}
}
