package main

import (
	"fmt"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/daemon"
	"github.com/pidginhost/csm/internal/integration/webserver"
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
// admission; the web peer log row reports per-request verification.
func webRewriteDoctorCheck(r checks.HTTPRewrite, cfg *config.Config) DoctorCheck {
	check := DoctorCheck{Name: "web client addresses", Status: "ok"}
	switch r.State {
	case checks.RewriteNone:
		check.Message = "no web server detected"
		if r.Server != platform.WSNone {
			check.Message = string(r.Server) + " configuration sets no client address rewriting"
		}
	case checks.RewriteActive:
		var trusted []string
		if cfg != nil {
			trusted = cfg.WebServer.TrustedProxies
		}
		if checks.NginxRealIPVerified(r, trusted) {
			check.Message = fmt.Sprintf("nginx takes client addresses only from Cloudflare's header and ranges or PROXY protocol from trusted proxies (%s in %s): verified, web findings are blocked as on a direct host", r.Directive, r.File)
			break
		}
		blocking := "existing blocking is unchanged"
		if r.Server == platform.WSLiteSpeed || r.Format {
			blocking = "while admission executes blocks, refused IP blocks stay refused; challenges still apply"
		}
		check.Message = fmt.Sprintf("%s logs a replaced client address (%s in %s): web findings get no automatic response from admission; %s", r.Server, r.Directive, r.File, blocking)
	default:
		check.Status = "warn"
		check.Message = "CSM cannot tell whether the web server rewrites client addresses: " + r.Reason + "; web findings get no automatic response from admission"
		check.Fix = "run csm doctor as root, then correct or make readable the web server configuration it names"
	}
	return check
}

// webPeerLogStale is how long the peer log may sit unwritten while the
// access log grows before the row says the web server is not writing it.
const webPeerLogStale = 15 * time.Minute

// webPeerLogDoctorCheck reports whether the web peer log lets admission
// verify the client addresses the web server rewrites.
func webPeerLogDoctorCheck(info platform.Info, r checks.HTTPRewrite, stat func(string) (os.FileInfo, error), now time.Time) DoctorCheck {
	check := DoctorCheck{Name: "web peer log", Status: "ok"}
	snippet := webserver.PeerLogPathFor(info)
	switch {
	case info.FrontProxied:
		check.Status = "warn"
		check.Message = "nginx runs in front of the web server, so the peer log cannot tell clients apart; rewritten web client addresses stay unverified"
		return check
	case info.ServerRunsSiteCode:
		check.Status = "warn"
		check.Message = "LiteSpeed PHP suEXEC is off or cannot be verified, so site code could alter the peer log; rewritten web client addresses stay unverified"
		check.Fix = "enable PHP suEXEC (1 or 2), reload LiteSpeed, then restart CSM"
		return check
	case snippet == "":
		check.Message = "not used with this web server"
		return check
	case r.State == checks.RewriteNone:
		check.Message = "not needed: the web server logs the connecting address"
		return check
	}
	if _, err := stat(snippet); err != nil {
		check.Status = "warn"
		check.Message = "not installed: run csm webserver-integration install so CSM can verify rewritten web client addresses"
		return check
	}
	logInfo, err := stat(webserver.PeerLogFile)
	if err != nil || now.Sub(logInfo.ModTime()) > webPeerLogStale {
		for _, access := range info.AccessLogPaths {
			if a, aerr := stat(access); aerr == nil && now.Sub(a.ModTime()) <= webPeerLogStale {
				check.Status = "warn"
				check.Message = "the web server is not writing " + webserver.PeerLogFile + "; reload it or run csm webserver-integration install again"
				return check
			}
		}
	}
	check.Message = "active: rewritten web client addresses are verified per request"
	return check
}
