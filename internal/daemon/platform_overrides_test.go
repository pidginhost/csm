package daemon

import (
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// The web_server: block is the operator's remedy for a wrong platform probe.
// Its mapping to platform overrides is one shared function, so the early
// install in the daemon command and the daemon's own startup agree.
func TestPlatformOverridesFromConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebServer.Type = "litespeed"
	cfg.WebServer.ConfigDir = "/etc/apache2"
	cfg.WebServer.AccessLogs = []string{"/var/log/lsws/access.log"}
	cfg.WebServer.ErrorLogs = []string{"/var/log/lsws/error.log"}
	cfg.WebServer.ModSecAudits = []string{"/var/log/lsws/modsec.log"}
	cfg.WebServer.DomlogGlobs = []string{"/home/*/logs/*"}

	o := PlatformOverridesFrom(cfg)
	if o.WebServer == nil || *o.WebServer != platform.WSLiteSpeed {
		t.Fatalf("webserver override = %v, want litespeed", o.WebServer)
	}
	if o.ApacheConfigDir != "/etc/apache2" || !slices.Equal(o.AccessLogPaths, cfg.WebServer.AccessLogs) ||
		!slices.Equal(o.ErrorLogPaths, cfg.WebServer.ErrorLogs) || !slices.Equal(o.ModSecAuditLogPaths, cfg.WebServer.ModSecAudits) ||
		!slices.Equal(o.DomlogGlobs, cfg.WebServer.DomlogGlobs) {
		t.Fatalf("overrides = %+v, want every web_server field carried over", o)
	}

	if o := PlatformOverridesFrom(&config.Config{}); o.WebServer != nil {
		t.Fatal("an empty web_server.type must leave the detected webserver alone")
	}
}
