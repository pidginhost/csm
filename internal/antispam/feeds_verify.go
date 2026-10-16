package antispam

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
)

// LoadedRBLRules reads `rspamadm configdump -j rbl` and returns the rules
// rspamd runs, sorted. rbl.lua merges the legacy rules key over rbls and
// skips a rule that is not an object, has disabled = true or enabled =
// false.
func LoadedRBLRules(out []byte) ([]string, error) {
	var dump struct {
		RBLs  map[string]json.RawMessage `json:"rbls"`
		Rules map[string]json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(out, &dump); err != nil || dump.RBLs == nil {
		return nil, errors.New("configdump rbl has no rbls object")
	}
	type state struct {
		object            bool
		enabled, disabled *bool
	}
	rules := make(map[string]state, len(dump.RBLs))
	for _, set := range []map[string]json.RawMessage{dump.RBLs, dump.Rules} {
		for name, raw := range set {
			var fields struct {
				Enabled  *bool `json:"enabled"`
				Disabled *bool `json:"disabled"`
			}
			if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &fields) != nil {
				// A value of another shape replaces the rule and never runs.
				rules[name] = state{}
				continue
			}
			st := rules[name]
			if !st.object {
				st = state{object: true}
			}
			if fields.Enabled != nil {
				st.enabled = fields.Enabled
			}
			if fields.Disabled != nil {
				st.disabled = fields.Disabled
			}
			rules[name] = st
		}
	}
	names := make([]string, 0, len(rules))
	for name, st := range rules {
		if st.object && (st.enabled == nil || *st.enabled) && (st.disabled == nil || !*st.disabled) {
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
