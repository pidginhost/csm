package antispam

import (
	"slices"
	"testing"
)

func TestLoadedRBLRules(t *testing.T) {
	got, err := LoadedRBLRules([]byte(`{"attached_maps":[],"rbls":{"csm_psbl":{"rbl":"psbl.surriel.com"},"csm_uribl":{}}}`))
	if err != nil || !slices.Equal(got, []string{"csm_psbl", "csm_uribl"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{`[]`, `{"rbls":[]}`, `{}`, `nope`} {
		if _, err := LoadedRBLRules([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// rbl.lua skips a rule that is not an object, is disabled or is turned
// off, and merges the legacy rules key into rbls.
func TestLoadedRBLRulesCountsOnlyActiveRules(t *testing.T) {
	for dump, want := range map[string][]string{
		`{"rbls":{"csm_psbl":false,"csm_uribl":{}}}`:                          {"csm_uribl"},
		`{"rbls":{"csm_psbl":{"enabled":false},"csm_uribl":{}}}`:              {"csm_uribl"},
		`{"rbls":{"csm_psbl":{"disabled":true},"csm_uribl":{}}}`:              {"csm_uribl"},
		`{"rbls":{"csm_psbl":{"enabled":true}},"rules":{"spamhaus":{}}}`:      {"csm_psbl", "spamhaus"},
		`{"rbls":{"csm_psbl":{}},"rules":{"csm_psbl":{"enabled":false}}}`:     nil,
		`{"rbls":{"csm_psbl":{},"csm_uribl":{}},"rules":{"csm_uribl":false}}`: {"csm_psbl"},
	} {
		got, err := LoadedRBLRules([]byte(dump))
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%s = %v, %v; want %v", dump, got, err, want)
		}
	}
}

func TestCheckFeedsLoaded(t *testing.T) {
	s := defaults(false)
	s.Feeds = []string{FeedPSBL, FeedSEM}
	on := map[string]bool{"rbl": true}
	if got := CheckFeedsLoaded(on, []string{"csm_psbl", "csm_sem", "csm_sem_ipv6"}, s); len(got) != 0 {
		t.Fatalf("exact rules flagged: %v", got)
	}
	for name, tc := range map[string]struct {
		enabled map[string]bool
		rules   []string
	}{
		"rbl off":    {map[string]bool{}, []string{"csm_psbl", "csm_sem", "csm_sem_ipv6"}},
		"extra rule": {on, []string{"csm_psbl", "csm_sem", "csm_sem_ipv6", "spamhaus"}},
		"rule lost":  {on, []string{"csm_psbl", "csm_sem"}},
	} {
		if got := CheckFeedsLoaded(tc.enabled, tc.rules, s); len(got) == 0 {
			t.Errorf("%s not flagged", name)
		}
	}
	if got := CheckFeedsLoaded(map[string]bool{}, nil, defaults(false)); len(got) != 0 {
		t.Fatalf("no DNS feeds and rbl off: %v", got)
	}
}
