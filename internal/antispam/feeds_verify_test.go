package antispam

import (
	"encoding/json"
	"slices"
	"strings"
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

// rbl.lua skips a disabled or turned-off rule and merges the legacy rules
// key into rbls. CSM renders rules empty, so any entry there, or a rule of
// another shape, cannot be verified.
func TestLoadedRBLRulesCountsOnlyActiveRules(t *testing.T) {
	for dump, want := range map[string][]string{
		`{"rbls":{"csm_psbl":{"enabled":false},"csm_uribl":{}}}`:           {"csm_uribl"},
		`{"rbls":{"csm_psbl":{"disabled":true},"csm_uribl":{}}}`:           {"csm_uribl"},
		`{"rbls":{"csm_psbl":{"enabled":true},"csm_uribl":{}},"rules":{}}`: {"csm_psbl", "csm_uribl"},
	} {
		got, err := LoadedRBLRules([]byte(dump))
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%s = %v, %v; want %v", dump, got, err, want)
		}
	}
	for _, dump := range []string{
		`{"rbls":{"csm_psbl":false,"csm_uribl":{}}}`,
		`{"rbls":{"csm_psbl":{"enabled":true}},"rules":{"spamhaus":{}}}`,
		`{"rbls":{"csm_psbl":{}},"rules":{"csm_psbl":{"enabled":false}}}`,
		`{"rbls":{"csm_psbl":{},"csm_uribl":{}},"rules":{"csm_uribl":false}}`,
	} {
		if got, err := LoadedRBLRules([]byte(dump)); err == nil {
			t.Errorf("%s = %v; want an error", dump, got)
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

func TestLoadedRBLRulesRejectsUnverifiableInventory(t *testing.T) {
	for name, dump := range map[string]string{
		"legacy extra":      `{"rbls":{"csm_psbl":{}},"rules":{"foreign":{}}}`,
		"legacy override":   `{"rbls":{"csm_psbl":{}},"rules":{"csm_psbl":{"enabled":false}}}`,
		"legacy list":       `{"rbls":{"csm_psbl":{}},"rules":[]}`,
		"legacy null":       `{"rbls":{"csm_psbl":{}},"rules":null}`,
		"wrong case":        `{"RBLs":{"csm_psbl":{}}}`,
		"duplicate section": `{"rbls":{"foreign":{}},"rbls":{"csm_psbl":{}}}`,
		"duplicate rule":    `{"rbls":{"csm_psbl":{"enabled":false},"csm_psbl":{}}}`,
		"duplicate flag":    `{"rbls":{"csm_psbl":{"enabled":false,"enabled":true}}}`,
		"null rule":         `{"rbls":{"csm_psbl":null}}`,
		"scalar rule":       `{"rbls":{"csm_psbl":false}}`,
		"list rule":         `{"rbls":{"csm_psbl":[]}}`,
		"nonboolean flag":   `{"rbls":{"csm_psbl":{"enabled":[true,false]}}}`,
		"null flag":         `{"rbls":{"csm_psbl":{"enabled":null}}}`,
		"string flag":       `{"rbls":{"csm_psbl":{"disabled":"false"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadedRBLRules([]byte(dump)); err == nil {
				t.Fatal("accepted an unverifiable rule inventory")
			}
		})
	}
}

func TestLoadedRBLRulesExcludesDisabledRules(t *testing.T) {
	for name, flags := range map[string]string{
		"enabled false": `"enabled":false`,
		"disabled true": `"disabled":true`,
		"both set":      `"enabled":true,"disabled":true`,
	} {
		t.Run(name, func(t *testing.T) {
			dump := `{"rbls":{"csm_psbl":{` + flags + `},"csm_sem":{"enabled":true,"disabled":false}},"rules":{}}`
			got, err := LoadedRBLRules([]byte(dump))
			if err != nil || !slices.Equal(got, []string{"csm_sem"}) {
				t.Fatal("disabled rule was counted as loaded, or active rule was lost")
			}
		})
	}
}

func TestLoadedRBLRulesErrorsDoNotExposeConfiguration(t *testing.T) {
	// Configuration output can contain a DQS key even in object keys and
	// malformed values. Diagnostics must never repeat any of that text.
	for _, dump := range []string{
		`{"rbls":` + testKey + `}`,
		`{"rbls":{"` + testKey + `":null}}`,
		`{"rbls":{"csm_psbl":{"enabled":"` + testKey + `"}}}`,
		`{"rbls":{"csm_psbl":{}},"rules":{"` + testKey + `":{}}}`,
	} {
		if _, err := LoadedRBLRules([]byte(dump)); err == nil || strings.Contains(err.Error(), testKey) {
			t.Fatal("invalid configuration must return an error without configuration text")
		}
	}
}

func TestRspamdComPaths(t *testing.T) {
	dump := []byte(`{
		"multimap": {"freemail_from": {"map": "https://maps.rspamd.com/freemail/free.txt.zst"}, "local": {"map": "/etc/x"}},
		"whitelist": {"rules": {"WHITELIST_DMARC": {"domains": ["https://maps.rspamd.com/rspamd/dmarc_whitelist_new.inc.zst"]}}},
		"fuzzy_check": {"rule": {"rspamd.com": {"servers": "service=fuzzy+rspamd.com"}}},
		"group": {"fuzzy": {"symbols": {"FUZZY_DENIED": {"description": "Denied by fuzzy from bl.rspamd.com"}}}}
	}`)
	got, err := RspamdComPaths(dump, map[string]bool{"multimap": true, "whitelist": true})
	want := []string{"multimap.freemail_from.map", "whitelist.rules.WHITELIST_DMARC.domains.0"}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("got %v, %v; want %v", got, err, want)
	}
	if _, err := RspamdComPaths([]byte("nope"), nil); err == nil {
		t.Fatal("accepted invalid JSON")
	}
}

func TestRspamdComPathsRemoteReferences(t *testing.T) {
	for name, tc := range map[string]struct {
		value string
		want  bool
	}{
		"https":          {"https://maps.rspamd.com/custom.txt", true},
		"http":           {"http://rspamd.com/custom.txt", true},
		"case and port":  {"https://MAPS.RSPAMD.COM.:443/custom.txt", true},
		"typed map":      {"glob;https://maps.rspamd.com/custom.txt", true},
		"signed map":     {"sign+key=example+https://maps.rspamd.com/custom.txt", true},
		"fallback map":   {"fallback+https://maps.rspamd.com/custom.txt", true},
		"DNS zone":       {"bl.rspamd.com", true},
		"server port":    {"fuzzy.rspamd.com:11335", true},
		"service":        {"service=fuzzy+rspamd.com", true},
		"local file":     {"/etc/rspamd/maps.d/maps.rspamd.com/custom.txt", false},
		"file URL":       {"file:///etc/rspamd/maps.rspamd.com.txt", false},
		"typed local":    {"glob;/etc/rspamd/maps.rspamd.com.txt", false},
		"fallback local": {"fallback+file:///etc/rspamd/maps.rspamd.com.txt", false},
		"description":    {"Local copy of maps.rspamd.com", false},
		"other host":     {"https://notrspamd.com/custom.txt", false},
		"host suffix":    {"https://rspamd.com.example.org/custom.txt", false},
		"URL path":       {"https://example.org/rspamd.com/custom.txt", false},
		"URL query":      {"https://example.org/map?source=rspamd.com", false},
		"URL user":       {"https://rspamd.com@example.org/custom.txt", false},
	} {
		t.Run(name, func(t *testing.T) {
			dump, err := json.Marshal(map[string]any{"multimap": map[string]any{"custom": map[string]string{"map": tc.value}}})
			if err != nil {
				t.Fatal(err)
			}
			got, err := RspamdComPaths(dump, map[string]bool{"multimap": true})
			var want []string
			if tc.want {
				want = []string{"multimap.custom.map"}
			}
			if err != nil || !slices.Equal(got, want) {
				t.Fatalf("paths = %v, error = %v; want %v", got, err, want)
			}
		})
	}
}

func TestRspamdComPathsRedactsSensitiveKeys(t *testing.T) {
	for name, key := range map[string]string{
		"DQS key":      testKey,
		"embedded key": "prefix_" + testKey + "_suffix",
		"URL key":      "https://example.org/private",
		"control key":  "custom\nprivate",
	} {
		t.Run(name, func(t *testing.T) {
			dump, err := json.Marshal(map[string]any{
				"multimap": map[string]any{key: map[string]string{"map": "https://maps.rspamd.com/" + testKey}},
			})
			if err != nil {
				t.Fatal("cannot encode test configuration")
			}
			got, err := RspamdComPaths(dump, map[string]bool{"multimap": true})
			if err != nil || !slices.Equal(got, []string{"multimap.[redacted].map"}) {
				t.Fatal("sensitive object key was not redacted, or the remote map was lost")
			}
		})
	}
}

func TestRspamdComPathsIgnoresSymbolGroups(t *testing.T) {
	dump := []byte(`{"group":{"symbols":{"description":"https://rspamd.com"}}}`)
	got, err := RspamdComPaths(dump, map[string]bool{"group": true})
	if err != nil || len(got) != 0 {
		t.Fatal("symbol group was treated as an enabled module")
	}
}

func TestRspamdComPathsRejectsNonObjects(t *testing.T) {
	for _, dump := range []string{`null`, `[]`, `true`, `"text"`, `{`, `{} {}`} {
		if got, err := RspamdComPaths([]byte(dump), nil); err == nil || len(got) != 0 {
			t.Fatal("invalid configuration must return an error without paths")
		}
	}
}

func TestCheckIPMapLoaded(t *testing.T) {
	good := `{"CSM_IP":{"type":"ip","map":"/var/lib/csm-rspamd/csm_ip.map","score":5.0,` +
		`"symbols":["CSM_IP_DROP","CSM_IP_BLOCKED","CSM_IP_MAIL_AUTH","CSM_IP_SPAM","CSM_IP_BLOCKLISTDE","CSM_IP_CINS","CSM_IP_CANARY"]},"freemail_from":{}}`
	if got := CheckIPMapLoaded(map[string]bool{"multimap": true}, []byte(good)); len(got) != 0 {
		t.Fatalf("good rule flagged: %v", got)
	}
	for name, dump := range map[string]string{
		"map list":          strings.Replace(good, `"map":"/var/lib/csm-rspamd/csm_ip.map"`, `"map":["/var/lib/csm-rspamd/csm_ip.map"]`, 1),
		"reordered symbols": strings.Replace(good, `"CSM_IP_DROP","CSM_IP_BLOCKED"`, `"CSM_IP_BLOCKED","CSM_IP_DROP"`, 1),
		"integer score":     strings.Replace(good, `"score":5.0`, `"score":5`, 1),
		"enabled":           strings.Replace(good, `"type":"ip"`, `"type":"ip","enabled":true`, 1),
	} {
		if got := CheckIPMapLoaded(map[string]bool{"multimap": true}, []byte(dump)); len(got) != 0 {
			t.Errorf("%s flagged: %v", name, got)
		}
	}
	for name, dump := range map[string]string{
		"zero score":  strings.Replace(good, `"score":5.0`, `"score":0`, 1),
		"high score":  strings.Replace(good, `"score":5.0`, `"score":50`, 1),
		"no score":    strings.Replace(good, `"score":5.0,`, ``, 1),
		"null score":  strings.Replace(good, `"score":5.0`, `"score":null`, 1),
		"score alias": strings.Replace(good, `"score":5.0`, `"Score":5.0`, 1),
		"type alias":  strings.Replace(good, `"type":"ip"`, `"Type":"ip"`, 1),
		"duplicate":   strings.Replace(good, `"type":"ip"`, `"type":"from","type":"ip"`, 1),
		"action":      strings.Replace(good, `"type":"ip"`, `"type":"ip","action":"accept"`, 1),
		"condition":   strings.Replace(good, `"type":"ip"`, `"type":"ip","require_symbols":"NEVER"`, 1),
		"null switch": strings.Replace(good, `"type":"ip"`, `"type":"ip","enabled":null`, 1),
		"missing":     `{"freemail_from":{}}`,
		"other map":   strings.Replace(good, "/var/lib/csm-rspamd/csm_ip.map", "/tmp/x.map", 1),
		"other type":  strings.Replace(good, `"type":"ip"`, `"type":"from"`, 1),
		"disabled":    strings.Replace(good, `"type":"ip"`, `"type":"ip","enabled":false`, 1),
		"symbol lost": strings.Replace(good, `,"CSM_IP_CANARY"`, ``, 1),
		"not a rule":  `{"CSM_IP":false}`,
		"unreadable":  `nope`,
	} {
		if got := CheckIPMapLoaded(map[string]bool{"multimap": true}, []byte(dump)); len(got) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
}
