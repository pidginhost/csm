package main

import (
	"fmt"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/daemon"
	"github.com/pidginhost/csm/internal/platform"
)

// doctorPlatformOverrides installs the loaded config's web_server: settings
// before any doctor check reads the platform, as the daemon does at start.
var doctorPlatformOverrides = daemon.InstallPlatformOverrides

// doctorHTTPRewrite reads this host's web server configuration, as the
// daemon does. Detection that ran before the web_server: settings could be
// applied describes another server, so the row cannot tell.
var doctorHTTPRewrite = func(overridesApplied bool) checks.HTTPRewrite {
	info := platform.Detect()
	if !overridesApplied {
		return checks.HTTPRewrite{Server: info.WebServer, Reason: "the web_server: settings were not applied because platform detection had already run"}
	}
	return checks.DetectHTTPRewrite(info)
}

// webRewriteDoctorCheck reports the rewriting state and its effect on
// admission. This build does not read a separate connecting peer field.
func webRewriteDoctorCheck(r checks.HTTPRewrite) DoctorCheck {
	check := DoctorCheck{Name: "web client addresses", Status: "ok"}
	switch r.State {
	case checks.RewriteNone:
		check.Message = "no web server detected"
		if r.Server != platform.WSNone {
			check.Message = string(r.Server) + " configuration sets no client address rewriting"
		}
	case checks.RewriteActive:
		check.Message = fmt.Sprintf("%s logs a replaced client address (%s in %s): web findings get no automatic response from admission; existing blocking is unchanged", r.Server, r.Directive, r.File)
	default:
		check.Status = "warn"
		check.Message = "CSM cannot tell whether the web server rewrites client addresses: " + r.Reason + "; web findings get no automatic response from admission"
		check.Fix = "run csm doctor as root, then correct or make readable the web server configuration it names"
	}
	return check
}
