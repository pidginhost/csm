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
}

// ParseActions reads `rspamadm configdump -j actions`. Keys other than the
// four CSM sets are ignored. Both underscored and spaced names are accepted;
// ambiguous aliases or a non-numeric, non-null value are errors.
func ParseActions(out []byte) (Actions, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(out, &raw); err != nil {
		return Actions{}, fmt.Errorf("configdump actions: %w", err)
	}
	if raw == nil {
		return Actions{}, errors.New("configdump actions: expected an object")
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
			if err := json.Unmarshal(v, &f); err != nil {
				return nil, fmt.Errorf("configdump action %s: %w", name, err)
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
	var err error
	for _, field := range []struct {
		key string
		dst **float64
	}{{"reject", &a.Reject}, {"add_header", &a.AddHeader}, {"greylist", &a.Greylist}, {"rewrite_subject", &a.RewriteSubject}} {
		if *field.dst, err = get(field.key); err != nil {
			return Actions{}, err
		}
	}
	return a, nil
}

// modulesOff must be inactive in the loaded configuration: core makes no
// third-party lookups and never defers mail.
var modulesOff = []string{"asn", "emails", "fuzzy_check", "greylist", "rbl"}

// CheckRspamd compares staged rspamd state with what CSM wrote. Each string
// names one conflict, such as an override.d file defeating a CSM setting.
func CheckRspamd(enabled map[string]bool, a Actions, s Settings) []string {
	return append(checkRspamdModules(enabled), checkRspamdActions(a, s)...)
}

func checkRspamdModules(enabled map[string]bool) []string {
	var out []string
	for _, m := range modulesOff {
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
