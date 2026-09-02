package daemon

import (
	"fmt"
	"os"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/platform"
)

// PlatformOverridesFrom maps the operator's web_server: block to platform
// overrides. WebServer is only set when a type was given, so an empty type
// leaves the detected webserver alone.
func PlatformOverridesFrom(cfg *config.Config) platform.Overrides {
	var wsOverride *platform.WebServer
	if t := cfg.WebServer.Type; t != "" {
		ws := platform.WebServer(t)
		wsOverride = &ws
	}
	return platform.Overrides{
		WebServer:           wsOverride,
		ApacheConfigDir:     cfg.WebServer.ConfigDir,
		AccessLogPaths:      cfg.WebServer.AccessLogs,
		ErrorLogPaths:       cfg.WebServer.ErrorLogs,
		ModSecAuditLogPaths: cfg.WebServer.ModSecAudits,
		DomlogGlobs:         cfg.WebServer.DomlogGlobs,
	}
}

// InstallPlatformOverrides installs the config-supplied platform overrides.
// It must run before anything in the process calls platform.Detect: a
// detection cached without them silently discards the operator's remedy for
// a wrong probe, so the daemon's log watchers attach to the wrong files. A
// lost override is reported loudly; the daemon keeps running on the probe.
func InstallPlatformOverrides(cfg *config.Config) bool {
	if platform.SetOverrides(PlatformOverridesFrom(cfg)) {
		return true
	}
	msg := "platform overrides from web_server: were ignored because platform detection ran first; log watchers follow the probe, not the config"
	fmt.Fprintf(os.Stderr, "[ERROR] %s\n", msg)
	obs.CaptureMsg("platform", msg)
	return false
}
