package webui

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/platform"
)

// featureTTL is how long a platform snapshot is reused. Detecting the mail
// server asks systemd, and a mail server can start after CSM does, so the
// snapshot is neither taken per request nor kept for the process lifetime.
const featureTTL = 5 * time.Minute

// cpanelMailBackend reports whether the cPanel/Exim adapters behind the mail
// queue, held copies, forwarders, deferrals and suspensions can run here. The
// API backends and the UI flags share it so a tab never shows without its API.
func cpanelMailBackend(info platform.Info) bool { return info.IsCPanel() }

// uiFeatures maps the detected panel and mail server to the named features
// the Web UI renders. Templates, the settings schema and the page scripts
// all read these names instead of testing the platform themselves.
func uiFeatures(info platform.Info, mta platform.MTAKind) map[string]bool {
	cp := cpanelMailBackend(info)
	return map[string]bool{
		"cpanel":          info.IsCPanel(),
		"mail":            cp || mta != platform.MTAUnknown,
		"mailQueue":       cp,
		"mailHeld":        cp,
		"mailForwarders":  cp,
		"mailDeferrals":   cp,
		"mailSuspensions": cp,
		"emailAV":         cp,
		"cphulk":          info.IsCPanel(),
	}
}

// featureSnapshot is one platform detection and the features derived from it.
type featureSnapshot struct {
	at       time.Time
	panel    platform.Panel
	mta      platform.MTAKind
	features map[string]bool
}

type featureState struct {
	// detectPlatform and featureNow are nil outside tests.
	detectPlatform func() (platform.Info, platform.MTAKind)
	featureNow     func() time.Time
	featureMu      sync.Mutex
	featureCache   featureSnapshot
}

func (s *Server) platformSnapshot() featureSnapshot {
	now := time.Now()
	if s.featureNow != nil {
		now = s.featureNow()
	}
	s.featureMu.Lock()
	defer s.featureMu.Unlock()
	if c := s.featureCache; c.features != nil && now.Sub(c.at) < featureTTL {
		return c
	}
	var info platform.Info
	var mta platform.MTAKind
	if s.detectPlatform != nil {
		info, mta = s.detectPlatform()
	} else {
		info, mta = platform.Detect(), platform.DetectMTA()
	}
	s.featureCache = featureSnapshot{at: now, panel: info.Panel, mta: mta, features: uiFeatures(info, mta)}
	return s.featureCache
}

// features returns the feature flags for this host. The map is shared;
// callers must not modify it.
func (s *Server) features() map[string]bool { return s.platformSnapshot().features }

// feature reports whether the named feature is available on this host.
// Unknown names are off.
func (s *Server) feature(name string) bool { return s.features()[name] }
