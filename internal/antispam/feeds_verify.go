package antispam

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
)

// LoadedRBLRules reads `rspamadm configdump -j rbl` and returns its rbls
// rule names, sorted.
func LoadedRBLRules(out []byte) ([]string, error) {
	var dump struct {
		RBLs map[string]json.RawMessage `json:"rbls"`
	}
	if err := json.Unmarshal(out, &dump); err != nil || dump.RBLs == nil {
		return nil, errors.New("configdump rbl has no rbls object")
	}
	names := make([]string, 0, len(dump.RBLs))
	for name := range dump.RBLs {
		names = append(names, name)
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
