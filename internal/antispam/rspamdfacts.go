package antispam

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var rspamdVersionRe = regexp.MustCompile(`(?i)\brspam(?:d daemon version|adm)\s+(\d{1,4})\.(\d{1,4})(?:\.(\d{1,4}))?(?:[ \t\r\n+-]|$)`)

// ParseRspamdDumpObject rejects ambiguous fields while preserving nested
// settings for the caller. Parse errors never include the dump's contents.
func ParseRspamdDumpObject(out []byte) (map[string]json.RawMessage, error) {
	return dumpObjectAs[json.RawMessage](out, "object")
}

// ParseRspamdVersion reads `rspamd --version` or `rspamadm --version` and
// returns the dotted version and its major number.
func ParseRspamdVersion(out string) (string, int, error) {
	m := rspamdVersionRe.FindStringSubmatch(out)
	if m == nil {
		return "", 0, errors.New("no rspamd version in output")
	}
	major, _ := strconv.Atoi(m[1])
	version := m[1] + "." + m[2]
	if m[3] != "" {
		version += "." + m[3]
	}
	return version, major, nil
}

// EnabledModules reads `rspamadm configdump -m` and returns the modules on its
// "Modules enabled:" line.
func EnabledModules(out string) (map[string]bool, error) {
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Modules enabled:")
		if !ok {
			continue
		}
		set := make(map[string]bool)
		for _, name := range strings.Split(rest, ",") {
			if name = strings.TrimSpace(name); name != "" {
				set[name] = true
			}
		}
		return set, nil
	}
	return nil, errors.New(`configdump output has no "Modules enabled:" line`)
}

// Actions are the loaded rspamd action thresholds. A nil field means the
// action is disabled or absent.
type Actions struct {
	Reject, AddHeader, Greylist, RewriteSubject *float64
	// GrowFactor rescales scores above the reject threshold; learning's
	// score table assumes none (spec 6.2).
	GrowFactor *float64
}

// ParseActions reads `rspamadm configdump -j actions`. Keys other than the
// four CSM sets and grow_factor are ignored. Underscored and spaced names
// are accepted; duplicate fields, ambiguous aliases and non-numeric,
// non-null values are errors.
func ParseActions(out []byte) (Actions, error) {
	raw, err := dumpObjectAs[json.RawMessage](out, "actions")
	if err != nil {
		return Actions{}, err
	}
	get := func(key string) (*float64, error) {
		names := []string{key}
		if alias := strings.ReplaceAll(key, "_", " "); alias != key {
			names = append(names, alias)
		}
		var value *float64
		seen := false
		for _, name := range names {
			v, ok := raw[name]
			if !ok {
				continue
			}
			var f *float64
			if decodeErr := json.Unmarshal(v, &f); decodeErr != nil {
				return nil, fmt.Errorf("configdump action %s: %w", name, decodeErr)
			}
			same := value == nil && f == nil || value != nil && f != nil && *value == *f
			if seen && !same {
				// The dump omits UCL priorities, so alias precedence is unknown.
				return nil, fmt.Errorf("configdump action %s: conflicting aliases %q and %q", key, key, name)
			}
			value, seen = f, true
		}
		return value, nil
	}
	var a Actions
	for _, field := range []struct {
		key string
		dst **float64
	}{{"reject", &a.Reject}, {"add_header", &a.AddHeader}, {"greylist", &a.Greylist}, {"rewrite_subject", &a.RewriteSubject}, {"grow_factor", &a.GrowFactor}} {
		if *field.dst, err = get(field.key); err != nil {
			return Actions{}, err
		}
	}
	return a, nil
}

// PhishtankEnabled reads `rspamadm configdump -j phishing` and reports
// whether the phishing module looks up message URLs in rspamd.com's
// phishtank zone. A missing or non-boolean setting is an error.
func PhishtankEnabled(out []byte) (bool, error) {
	fields, err := dumpObject(out, "phishing")
	if err != nil {
		return false, err
	}
	on, ok := fields["phishtank_enabled"].(bool)
	if !ok {
		return false, errors.New("configdump phishing: phishtank_enabled is not a boolean")
	}
	return on, nil
}

// modulesOff must be inactive in the loaded configuration: core makes no
// third-party lookups and never defers mail.
var modulesOff = []string{"asn", "emails", "fuzzy_check", "greylist", "rbl"}

// CheckRspamd compares staged rspamd state with what CSM wrote. Each string
// names one conflict, such as an override.d file defeating a CSM setting.
func CheckRspamd(enabled map[string]bool, a Actions, s Settings) []string {
	return append(checkRspamdModules(enabled, s), checkRspamdActions(a, s)...)
}

func checkRspamdModules(enabled map[string]bool, s Settings) []string {
	var out []string
	dns := len(s.DNSFeeds()) > 0
	for _, m := range modulesOff {
		// With a DNS feed rbl runs CSM's rules; CheckFeedsLoaded checks them.
		if m == "rbl" && dns {
			continue
		}
		// With learning fuzzy_check runs CSM's rules; learning verifies it,
		// and a learning fault never removes core filtering.
		if m == "fuzzy_check" && s.Learning {
			continue
		}
		if enabled[m] {
			out = append(out, fmt.Sprintf("rspamd module %s is enabled; an override defeats CSM's %s.conf", m, m))
		}
	}
	return out
}

func checkRspamdActions(a Actions, s Settings) []string {
	var out []string
	if !equals(a.Reject, s.RejectScore) {
		out = append(out, fmt.Sprintf("rspamd reject threshold is %s, want %d", show(a.Reject), s.RejectScore))
	}
	if !equals(a.AddHeader, s.TagScore) {
		out = append(out, fmt.Sprintf("rspamd add_header threshold is %s, want %d", show(a.AddHeader), s.TagScore))
	}
	if a.Greylist != nil {
		out = append(out, "rspamd greylist action is enabled")
	}
	if a.RewriteSubject != nil {
		out = append(out, "rspamd rewrite_subject action is enabled")
	}
	return out
}

func equals(v *float64, want int) bool { return v != nil && *v == float64(want) }

func show(v *float64) string {
	if v == nil {
		return "disabled"
	}
	return strconv.FormatFloat(*v, 'g', -1, 64)
}
