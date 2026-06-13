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
		{"no rdns suffixes", []VerifiedBot{{Name: "x", UASubstrings: []string{"xbotcrawler"}}}, true},
		{"bare tld suffix", []VerifiedBot{{Name: "x", UASubstrings: []string{"xbotcrawler"}, RDNSSuffixes: []string{"com"}}}, true},
		{"two-label public suffix", []VerifiedBot{{Name: "x", UASubstrings: []string{"xbotcrawler"}, RDNSSuffixes: []string{"co.uk"}}}, true},
		{"shared cloud suffix", []VerifiedBot{{Name: "x", UASubstrings: []string{"xbotcrawler"}, RDNSSuffixes: []string{"amazonaws.com"}}}, true},
		{"shared cloud subdomain suffix", []VerifiedBot{{Name: "x", UASubstrings: []string{"xbotcrawler"}, RDNSSuffixes: []string{"compute.amazonaws.com"}}}, true},
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
