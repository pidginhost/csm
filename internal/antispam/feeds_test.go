package antispam

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func symbolFor(z Zone, answer string) string {
	for _, c := range z.Codes {
		if slices.Contains(c.Answers, answer) {
			return c.Symbol
		}
	}
	return ""
}

func TestCatalogueInvariants(t *testing.T) {
	names, rules, symbols := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, f := range catalogue {
		if names[f.Name] {
			t.Errorf("feed %s is listed twice", f.Name)
		}
		names[f.Name] = true
		if f.Terms == "" {
			t.Errorf("%s has no terms note", f.Name)
		}
		var total float64
		probed := false
		for _, z := range f.Zones {
			if !strings.HasPrefix(z.Rule, "csm_") || strings.ToLower(z.Rule) != z.Rule || rules[z.Rule] {
				t.Errorf("%s: rule %q must be unique, lowercase and start with csm_", f.Name, z.Rule)
			}
			rules[z.Rule] = true
			zone := strings.ToLower(z.Zone)
			if strings.HasSuffix(zone, "rspamd.com") || strings.HasSuffix(zone, ".spamhaus.org") {
				t.Errorf("%s: zone %s is excluded by the terms review", f.Name, z.Zone)
			}
			if strings.Contains(z.Zone, dqsKeyMark) != f.NeedsKey {
				t.Errorf("%s: zone %s and NeedsKey disagree", f.Name, z.Zone)
			}
			if z.Domain == (z.IPv4 || z.IPv6) {
				t.Errorf("%s: zone %s must be either a domain list or an IP list", f.Name, z.Zone)
			}
			if z.TestName != "" {
				probed = true
				if len(z.TestAnswers) == 0 {
					t.Errorf("%s: zone %s has a test point without answers", f.Name, z.Zone)
				}
			}
			seen := map[string]bool{}
			for _, c := range z.Codes {
				if !strings.HasPrefix(c.Symbol, "CSM_") || symbols[c.Symbol] {
					t.Errorf("%s: symbol %q must be unique and start with CSM_", f.Name, c.Symbol)
				}
				symbols[c.Symbol] = true
				if c.Weight > 5 || c.Weight < -5 {
					t.Errorf("%s: %s weighs %v; the cap is 5", f.Name, c.Symbol, c.Weight)
				}
				if c.Description == "" || strings.ContainsAny(c.Description, "\"\\\n") || strings.ContainsFunc(c.Description, func(r rune) bool { return r > '~' }) {
					t.Errorf("%s: %s needs a plain ASCII description without quotes", f.Name, c.Symbol)
				}
				if len(c.Answers) == 0 {
					t.Errorf("%s: %s has no answers", f.Name, c.Symbol)
				}
				for _, a := range c.Answers {
					ip, err := netip.ParseAddr(a)
					if err != nil || !ip.Is4() || ip.As4()[0] != 127 {
						t.Errorf("%s: %s answer %q is not a 127.0.0.0/8 address", f.Name, c.Symbol, a)
					}
					if seen[a] {
						t.Errorf("%s: answer %s maps to two symbols", f.Name, a)
					}
					seen[a] = true
					if _, isErr := f.Errors[a]; isErr {
						t.Errorf("%s: error answer %s must never score", f.Name, a)
					}
				}
				// Different domains in one message can trigger every symbol
				// in a zone, even when each answer selects just one symbol.
				total += max(0, c.Weight)
			}
		}
		if f.DNS() && !probed {
			t.Errorf("%s has no zone the probe can test", f.Name)
		}
		if total >= DefaultRejectScore {
			t.Errorf("%s can add %v alone, at or above the default reject score", f.Name, total)
		}
	}
}

func TestBitListsFireOneSymbolPerAnswer(t *testing.T) {
	uribl, _ := FeedByName(FeedURIBL)
	surbl, _ := FeedByName(FeedSURBL)
	for _, tc := range []struct {
		zone         Zone
		answer, want string
	}{
		{uribl.Zones[0], "127.0.0.14", "CSM_URIBL_BLACK"},
		{uribl.Zones[0], "127.0.0.12", "CSM_URIBL_GREY"},
		{uribl.Zones[0], "127.0.0.8", "CSM_URIBL_RED"},
		{uribl.Zones[0], "127.0.0.255", ""},
		{uribl.Zones[0], "127.0.0.1", ""},
		{surbl.Zones[0], "127.0.0.254", "CSM_SURBL_PH"},
		{surbl.Zones[0], "127.0.0.48", "CSM_SURBL_MW"},
		{surbl.Zones[0], "127.0.0.36", "CSM_SURBL_CT"},
		{surbl.Zones[0], "127.0.0.2", ""},
	} {
		if got := symbolFor(tc.zone, tc.answer); got != tc.want {
			t.Errorf("%s %s = %q, want %q", tc.zone.Zone, tc.answer, got, tc.want)
		}
	}
}

func TestDNSWLLeavesTestCategoryUnscored(t *testing.T) {
	dnswl, _ := FeedByName(FeedDNSWL)
	z := dnswl.Zones[0]
	if got := symbolFor(z, "127.0.10.0"); got != "" {
		t.Errorf("127.0.10.0 scores as %s", got)
	}
	if got := symbolFor(z, "127.0.15.3"); got != "CSM_DNSWL_HI" {
		t.Errorf("127.0.15.3 = %q, want CSM_DNSWL_HI", got)
	}
}

func TestFeedByName(t *testing.T) {
	if f, ok := FeedByName(FeedPSBL); !ok || f.Name != FeedPSBL {
		t.Fatalf("psbl = %+v, %v", f, ok)
	}
	if _, ok := FeedByName("csm_ip_map"); ok {
		t.Fatal("csm_ip_map belongs to plan B")
	}
	if got := FeedNames(); len(got) != len(catalogue) || got[0] != FeedMailspike {
		t.Fatalf("FeedNames = %v", got)
	}
}

func TestFeedByNameReturnsIndependentData(t *testing.T) {
	// Preserve the catalogue even if a shallow copy lets this test change it.
	original := catalogue
	data, err := json.Marshal(catalogue)
	if err != nil {
		t.Fatal(err)
	}
	var testCatalogue []Feed
	if err := json.Unmarshal(data, &testCatalogue); err != nil {
		t.Fatal(err)
	}
	catalogue = testCatalogue
	t.Cleanup(func() { catalogue = original })

	for _, want := range original {
		f, ok := FeedByName(want.Name)
		if !ok {
			t.Fatalf("missing feed %s", want.Name)
		}
		for i := range f.Zones {
			z := &f.Zones[i]
			z.Zone = "changed.invalid"
			for j := range z.TestAnswers {
				z.TestAnswers[j] = "changed"
			}
			for j := range z.Codes {
				z.Codes[j].Weight = 100
				for k := range z.Codes[j].Answers {
					z.Codes[j].Answers[k] = "changed"
				}
			}
		}
		for answer := range f.Errors {
			f.Errors[answer] = "changed"
		}
		got, ok := FeedByName(want.Name)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("mutating returned feed changed catalogue entry %s", want.Name)
		}
	}
}

func TestSpamhausZENIncludesBCL(t *testing.T) {
	f, ok := FeedByName(FeedSpamhausDQS)
	if !ok {
		t.Fatal("missing Spamhaus DQS feed")
	}
	// Spamhaus documents BCL as part of ZEN at:
	// https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/040-zones.html
	for _, z := range f.Zones {
		if z.Rule == "csm_dqs_zen" {
			if got := symbolFor(z, "127.0.0.30"); got != "CSM_DQS_ZEN" {
				t.Fatalf("BCL answer mapped to %q, want CSM_DQS_ZEN", got)
			}
			return
		}
	}
	t.Fatal("missing ZEN zone")
}

func TestValidateFeeds(t *testing.T) {
	for _, tc := range []struct {
		names   []string
		keyFile string
		wantErr string
	}{
		{nil, "", ""},
		{[]string{FeedPSBL, FeedRspamdMaps}, "", ""},
		{[]string{"nope"}, "", `unknown feed "nope"`},
		{[]string{FeedPSBL, FeedPSBL}, "", "listed twice"},
		{[]string{FeedSpamhausDQS}, "", "needs spamhaus_dqs_key_file"},
		{[]string{FeedSpamhausDQS}, "etc/key", "clean absolute path"},
		{[]string{FeedSpamhausDQS}, "/etc/csm/../key", "clean absolute path"},
		{[]string{FeedSpamhausDQS}, "/", "file path"},
		{[]string{FeedSpamhausDQS}, "/etc/csm/key\x00", "file path"},
		{[]string{FeedSpamhausDQS}, "/etc/csm/spamhaus-dqs.key", ""},
	} {
		err := ValidateFeeds(tc.names, tc.keyFile)
		if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("ValidateFeeds(%v, %q) = %v, want %q", tc.names, tc.keyFile, err, tc.wantErr)
		}
	}
}
