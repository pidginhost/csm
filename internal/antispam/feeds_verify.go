package antispam

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
)

// LoadedRBLRules reads `rspamadm configdump -j rbl` and returns enabled
// rbls rule names, sorted. Ambiguous entries and legacy overrides are errors.
func LoadedRBLRules(out []byte) ([]string, error) {
	dump, err := dumpObjectAs[json.RawMessage](out, "rbl")
	if err != nil {
		return nil, err
	}
	rules, err := dumpObjectAs[json.RawMessage](dump["rbls"], "rbl rules")
	if err != nil {
		return nil, err
	}
	if raw, present := dump["rules"]; present {
		// Rspamd merges the legacy alias into rbls, including overrides
		// of names already there. CSM renders this object empty.
		legacy, err := dumpObjectAs[json.RawMessage](raw, "rbl legacy rules")
		if err != nil || len(legacy) != 0 {
			return nil, errors.New("configdump rbl has legacy rule overrides")
		}
	}
	names := make([]string, 0, len(rules))
	for name, raw := range rules {
		rule, err := dumpObjectAs[json.RawMessage](raw, "rbl rule")
		if err != nil {
			return nil, err
		}
		enabled, disabled := true, false
		for _, flag := range []struct {
			key   string
			value *bool
		}{{"enabled", &enabled}, {"disabled", &disabled}} {
			if raw, present := rule[flag.key]; present {
				// A null or non-boolean flag cannot prove the rule is on.
				var value *bool
				if err := json.Unmarshal(raw, &value); err != nil || value == nil {
					return nil, errors.New("configdump rbl has a non-boolean rule switch")
				}
				*flag.value = *value
			}
		}
		if enabled && !disabled {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// CheckFeedsLoaded compares rspamd's loaded rbl state with s: the module
// is on exactly when s has a DNS feed, and its rules are exactly CSM's.
// Each string names one difference; none repeats configuration text.
func CheckFeedsLoaded(enabled map[string]bool, rules []string, s Settings) []string {
	var want []string
	for _, f := range s.DNSFeeds() {
		for _, z := range f.Zones {
			want = append(want, z.Rule)
		}
	}
	if len(want) == 0 {
		return nil // rbl must be off; checkRspamdModules reports it
	}
	if !enabled["rbl"] {
		return []string{"rspamd's rbl module is off, so no DNS feed runs; an override defeats CSM's local.d/rbl.conf"}
	}
	sort.Strings(want)
	var out []string
	for _, r := range want {
		if !slices.Contains(rules, r) {
			out = append(out, fmt.Sprintf("rspamd did not load CSM's rule %s", r))
		}
	}
	extra := 0
	for _, r := range rules {
		if !slices.Contains(want, r) {
			extra++
		}
	}
	if extra > 0 {
		out = append(out, fmt.Sprintf("rspamd loaded %d blocklist rules CSM did not write; an override adds them next to CSM's override.d/rbl.conf", extra))
	}
	return out
}
