package webui

import (
	"maps"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/phpshield"
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

// uiFeatures maps the detected panel, mail server and PHP install to the
// named features the Web UI renders. Templates, the settings schema and the
// page scripts all read these names instead of testing the platform
// themselves.
func uiFeatures(info platform.Info, mta platform.MTAKind, php phpPresence) map[string]bool {
	cp := cpanelMailBackend(info)
	return map[string]bool{
		"cpanel":          info.IsCPanel(),
		"mail":            cp || mta != platform.MTAUnknown,
		"mailQueue":       cp,
		"mailHeld":        cp,
		"mailForwarders":  cp,
		"mailDeferrals":   cp,
		"mailSuspensions": cp || mta == platform.MTAStalwart,
		"emailAV":         cp,
		"cphulk":          info.IsCPanel(),
		"stalwartFilter":  mta == platform.MTAStalwart,
		"php":             php.php,
		"phpShield":       php.shield,
	}
}

// Tests replace these probes so constructing a server never depends on the build host.
var hostPlatform = func() (platform.Info, platform.MTAKind) {
	return platform.Detect(), platform.DetectMTA()
}
var hostPHP = platform.DetectPHP

type phpPresence struct{ php, shield bool }

type featureState struct {
	featureCache       atomic.Pointer[map[string]bool]
	detectPlatform     func() (platform.Info, platform.MTAKind)
	detectContainerPHP func() (bool, bool)
}

func (s *Server) hostFeatures() map[string]bool {
	detect := s.detectPlatform
	if detect == nil {
		detect = hostPlatform
	}
	info, mta := detect()
	php := hostPHP()
	return uiFeatures(info, mta, phpPresence{php: php, shield: php})
}

// watchFeatures is the sole writer after startup. A slow probe leaves the
// last complete snapshot available to every request, including the first.
func (s *Server) watchFeatures() {
	detect := s.detectContainerPHP
	if detect == nil {
		detect = func() (bool, bool) { return scanPHPProcesses("/proc", phpshield.ScriptPath) }
	}
	ticker := time.NewTicker(featureTTL)
	defer ticker.Stop()
	features := maps.Clone(s.features())
	for {
		if !features["php"] {
			features["php"], features["phpShield"] = detect()
		}
		s.setFeatures(features)
		select {
		case <-s.pruneDone:
			return
		case <-ticker.C:
		}
		features = s.hostFeatures()
	}
}

func (s *Server) setFeatures(features map[string]bool) { s.featureCache.Store(&features) }

// features returns an immutable snapshot.
func (s *Server) features() map[string]bool {
	if f := s.featureCache.Load(); f != nil {
		return *f
	}
	return nil
}

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
