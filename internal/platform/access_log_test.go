package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCPanelCentralAccessLogProvenance(t *testing.T) {
	for _, tc := range []struct {
		name string
		info Info
		path string
		want bool
	}{
		{"cpanel Apache", Info{Panel: PanelCPanel, WebServer: WSApache}, "/usr/local/apache/logs/access_log", true},
		{"cpanel LiteSpeed", Info{Panel: PanelCPanel, WebServer: WSLiteSpeed}, "/usr/local/lsws/logs/access.log", true},
		{"plain Apache", Info{WebServer: WSApache}, "/usr/local/apache/logs/access_log", false},
		{"plain LiteSpeed", Info{WebServer: WSLiteSpeed}, "/usr/local/lsws/logs/access.log", false},
		{"custom candidate", Info{Panel: PanelCPanel, WebServer: WSApache, AccessLogPaths: []string{"/srv/logs/site.example.log"}}, "/srv/logs/site.example.log", false},
		{"empty", Info{Panel: PanelCPanel}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.info.IsCPanelCentralAccessLog(tc.path); got != tc.want {
				t.Fatalf("central provenance = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCPanelCentralAccessLogRelativePath(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	path, err := filepath.Rel(wd, "/usr/local/apache/logs/access_log")
	if err != nil {
		t.Fatal(err)
	}
	info := Info{Panel: PanelCPanel, WebServer: WSApache}
	if !info.IsCPanelCentralAccessLog(path) {
		t.Fatal("a relative path to the central log lost its provenance")
	}
}
