package config

import (
	"strings"
	"testing"
)

func verifiedBotErrors(cfg *Config) []ValidationResult {
	var got []ValidationResult
	for _, r := range Validate(cfg) {
		if r.Level == "error" && strings.HasPrefix(r.Field, "reputation.verified_bots") {
			got = append(got, r)
		}
	}
	return got
}

func TestValidateVerifiedBots(t *testing.T) {
	valid := VerifiedBot{
		Name:         "seranking",
		UASubstrings: []string{"serankingbacklinksbot"},
		RDNSSuffixes: []string{"seranking.com"},
	}
	cases := []struct {
		name    string
		bots    []VerifiedBot
		wantErr bool
	}{
		{"valid", []VerifiedBot{valid}, false},
		{"valid multi-label suffix", []VerifiedBot{{Name: "x", UASubstrings: []string{"xbotcrawler"}, RDNSSuffixes: []string{"crawl.x.example"}}}, false},
		{"empty name", []VerifiedBot{{UASubstrings: []string{"serankingbacklinksbot"}, RDNSSuffixes: []string{"seranking.com"}}}, true},
		{"duplicate name", []VerifiedBot{valid, valid}, true},
		{"no ua substrings", []VerifiedBot{{Name: "x", RDNSSuffixes: []string{"x.example"}}}, true},
		{"ua substring too short", []VerifiedBot{{Name: "x", UASubstrings: []string{"ab"}, RDNSSuffixes: []string{"x.example"}}}, true},
		{"ua substring browser token", []VerifiedBot{{Name: "x", UASubstrings: []string{"Mozilla"}, RDNSSuffixes: []string{"x.example"}}}, true},
		{"ua substring browser prefix", []VerifiedBot{{Name: "x", UASubstrings: []string{"Mozilla/5.0"}, RDNSSuffixes: []string{"x.example"}}}, true},
		{"ua substring browser prefix with crawler token", []VerifiedBot{{Name: "x", UASubstrings: []string{"Mozilla/5.0 (compatible; AcmeCrawler)"}, RDNSSuffixes: []string{"x.example"}}}, false},
		{"duplicate ua substring across bots", []VerifiedBot{
			valid,
			{Name: "x", UASubstrings: []string{"SERankingBacklinksBot"}, RDNSSuffixes: []string{"x.example"}},
		}, true},
		{"overlapping ua substring across bots", []VerifiedBot{
			{Name: "x", UASubstrings: []string{"acmecrawler"}, RDNSSuffixes: []string{"x.example"}},
			{Name: "y", UASubstrings: []string{"crawler"}, RDNSSuffixes: []string{"y.example"}},
		}, true},
		{"no rdns suffixes", []VerifiedBot{{Name: "x", UASubstrings: []string{"xbotcrawler"}}}, true},
		{"bare tld suffix", []VerifiedBot{{Name: "x", UASubstrings: []string{"xbotcrawler"}, RDNSSuffixes: []string{"com"}}}, true},
		{"two-label public suffix", []VerifiedBot{{Name: "x", UASubstrings: []string{"xbotcrawler"}, RDNSSuffixes: []string{"co.uk"}}}, true},
		{"shared cloud suffix", []VerifiedBot{{Name: "x", UASubstrings: []string{"xbotcrawler"}, RDNSSuffixes: []string{"amazonaws.com"}}}, true},
		{"shared cloud subdomain suffix", []VerifiedBot{{Name: "x", UASubstrings: []string{"xbotcrawler"}, RDNSSuffixes: []string{"compute.amazonaws.com"}}}, true},
		{"wildcard suffix", []VerifiedBot{{Name: "x", UASubstrings: []string{"xbotcrawler"}, RDNSSuffixes: []string{"*.example.com"}}}, true},
		{"leading hyphen suffix", []VerifiedBot{{Name: "x", UASubstrings: []string{"xbotcrawler"}, RDNSSuffixes: []string{"-crawl.example.com"}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Reputation.VerifiedBots = tc.bots
			got := verifiedBotErrors(cfg)
			if tc.wantErr && len(got) == 0 {
				t.Errorf("want a validation error, got none")
			}
			if !tc.wantErr && len(got) != 0 {
				t.Errorf("want no validation error, got %v", got)
			}
		})
	}
}

func TestLoadBytesValidatesVerifiedBots(t *testing.T) {
	_, err := LoadBytes([]byte(`
reputation:
  verified_bots:
    - name: acmebot
      ua_substrings: ["acmecrawler"]
      rdns_suffixes: ["amazonaws.com"]
`))
	if err == nil {
		t.Fatal("LoadBytes accepted a shared-hosting verified bot suffix")
	}
	if !strings.Contains(err.Error(), "reputation.verified_bots[0].rdns_suffixes") {
		t.Fatalf("LoadBytes error = %v, want verified_bots field", err)
	}
}

func TestLoadBytesAcceptsNormalizedVerifiedBots(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
reputation:
  verified_bots:
    - name: " AcmeBot "
      ua_substrings: [" AcmeCrawler "]
      rdns_suffixes: [" .Acme.Example "]
`))
	if err != nil {
		t.Fatalf("LoadBytes valid verified_bots: %v", err)
	}
	if got := cfg.Reputation.VerifiedBots[0].RDNSSuffixes[0]; got != " .Acme.Example " {
		t.Fatalf("LoadBytes should preserve operator YAML value, got %q", got)
	}
}

func TestValidateVerifiedBots_IPRanges(t *testing.T) {
	cases := []struct {
		name    string
		bot     VerifiedBot
		wantErr bool
	}{
		{"ip_ranges only (no rdns) ok", VerifiedBot{Name: "perplexitybot", UASubstrings: []string{"perplexitybot"}, IPRanges: []string{"18.97.9.96/29"}}, false},
		{"single ip ok", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"18.97.1.229"}}, false},
		{"rdns and ip_ranges ok", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, RDNSSuffixes: []string{"x.example"}, IPRanges: []string{"74.7.241.0/25"}}, false},
		{"mapped ipv4 range ok", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"::ffff:74.7.241.0/120"}}, false},
		{"neither rdns nor ip_ranges", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}}, true},
		{"invalid cidr", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"not-a-cidr"}}, true},
		{"too broad v4", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"8.0.0.0/8"}}, true},
		{"too broad mapped ipv4", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"::ffff:8.0.0.0/104"}}, true},
		{"all mapped ipv4", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"::ffff:0.0.0.0/96"}}, true},
		{"default route", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"0.0.0.0/0"}}, true},
		{"this-network range", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"0.1.0.0/16"}}, true},
		{"private range", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"192.168.0.0/24"}}, true},
		{"mapped private range", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"::ffff:192.168.0.0/120"}}, true},
		{"loopback range", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"127.0.0.0/24"}}, true},
		{"carrier-grade NAT range", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"100.64.0.0/16"}}, true},
		{"6to4 anycast range", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"192.88.99.0/24"}}, true},
		{"benchmarking range", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"198.18.0.0/16"}}, true},
		{"documentation range", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"203.0.113.0/24"}}, true},
		{"IPv6 documentation range", VerifiedBot{Name: "x", UASubstrings: []string{"xbotcrawler"}, IPRanges: []string{"2001:db8::/32"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Reputation.VerifiedBots = []VerifiedBot{tc.bot}
			got := verifiedBotErrors(cfg)
			if tc.wantErr && len(got) == 0 {
				t.Errorf("want a validation error, got none")
			}
			if !tc.wantErr && len(got) != 0 {
				t.Errorf("want no validation error, got %v", got)
			}
		})
	}
}
