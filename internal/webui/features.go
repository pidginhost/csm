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
	features map[string]bool
}

// hostPlatform detects this host's panel and mail server. The package tests
// replace it so no test depends on what the build host runs.
var hostPlatform = func() (platform.Info, platform.MTAKind) {
	return platform.Detect(), platform.DetectMTA()
}

type featureState struct {
	// detectPlatform and featureNow are nil outside tests.
	detectPlatform func() (platform.Info, platform.MTAKind)
	featureNow     func() time.Time
	featureMu      sync.Mutex
	featureCache   featureSnapshot
	// featureRefreshing is set while one caller re-detects; the others
	// keep the previous snapshot instead of waiting on systemd.
	featureRefreshing bool
}

func (s *Server) platformSnapshot() featureSnapshot {
	now := time.Now()
	if s.featureNow != nil {
		now = s.featureNow()
	}
	s.featureMu.Lock()
	c := s.featureCache
	if c.features != nil && (now.Sub(c.at) < featureTTL || s.featureRefreshing) {
		s.featureMu.Unlock()
		return c
	}
	s.featureRefreshing = c.features != nil
	s.featureMu.Unlock()

	// Detection runs unlocked: it can wait on systemd for seconds.
	var info platform.Info
	var mta platform.MTAKind
	if s.detectPlatform != nil {
		info, mta = s.detectPlatform()
	} else {
		info, mta = hostPlatform()
	}
	snap := featureSnapshot{at: now, features: uiFeatures(info, mta)}
	s.featureMu.Lock()
	s.featureCache = snap
	s.featureRefreshing = false
	s.featureMu.Unlock()
	return snap
}

// features returns the feature flags for this host. The map is shared;
// callers must not modify it.
func (s *Server) features() map[string]bool { return s.platformSnapshot().features }

// feature reports whether the named feature is available on this host.
// Unknown names are off.
func (s *Server) feature(name string) bool { return s.features()[name] }

// filterSettingsSection returns sec as a host with the given features sees
// it: ok is false when the section itself needs a missing feature, and
// fields that need one are left out. The schema is not modified.
func filterSettingsSection(sec SettingsSection, features map[string]bool) (SettingsSection, bool) {
	if sec.Feature != "" && !features[sec.Feature] {
		return SettingsSection{}, false
	}
	fields := make([]SettingsField, 0, len(sec.Fields))
	for _, f := range sec.Fields {
		if f.Feature == "" || features[f.Feature] {
			fields = append(fields, f)
		}
	}
	sec.Fields = fields
	return sec, true
}

// settingsSections lists the settings sections this host shows.
func (s *Server) settingsSections() []SettingsSection {
	features := s.features()
	all := AllSettingsSections()
	out := make([]SettingsSection, 0, len(all))
	for _, sec := range all {
		if f, ok := filterSettingsSection(sec, features); ok {
			out = append(out, f)
		}
	}
	return out
}

// lookupSettingsSection returns a section as this host shows it. Reads and
// saves both go through it, so a hidden field is neither returned nor
// accepted, and its value on disk stays as it is.
func (s *Server) lookupSettingsSection(id string) (SettingsSection, bool) {
	sec, ok := LookupSettingsSection(id)
	if !ok {
		return SettingsSection{}, false
	}
	return filterSettingsSection(sec, s.features())
}
