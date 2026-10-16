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
