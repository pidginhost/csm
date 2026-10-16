package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAntispamFeedTypes(t *testing.T) {
	for _, enabled := range []string{"false", "true"} {
		for name, body := range map[string]string{
			"null name":       "enabled: [psbl, null]",
			"boolean name":    "enabled: [false]",
			"integer name":    "enabled: [12]",
			"fractional name": "enabled: [1.5]",
			"timestamp name":  "enabled: [2026-01-01]",
			"null alias":      "enabled: [&unset null, *unset]",
			"merged names":    "<<: {enabled: [psbl, null]}",
			"list alias":      "<<: {enabled: &names [null]}\n      enabled: *names",
			"boolean path":    "spamhaus_dqs_key_file: false",
			"integer path":    "spamhaus_dqs_key_file: 12",
			"fractional path": "spamhaus_dqs_key_file: 1.5",
			"timestamp path":  "spamhaus_dqs_key_file: 2026-01-01",
			"merged path":     "<<: {spamhaus_dqs_key_file: false}",
		} {
			t.Run(enabled+"/"+name, func(t *testing.T) {
				_, err := loadAntispam(t, "    enabled: "+enabled+"\n    feeds:\n      "+body+"\n")
				if err == nil || !strings.Contains(err.Error(), "email_protection.antispam.feeds") || !strings.Contains(err.Error(), "string") {
					t.Fatalf("expected a feed type error, got %v", err)
				}
			})
		}
	}
}

func TestAntispamFeedTypesPreserveStringsAndDefaults(t *testing.T) {
	for name, body := range map[string]string{
		"direct":      "    feeds:\n      enabled: [psbl, uribl]\n      spamhaus_dqs_key_file: /etc/csm/dqs.key\n",
		"block alias": "    <<: {feeds: &feeds {enabled: [psbl, uribl], spamhaus_dqs_key_file: /etc/csm/dqs.key}}\n    feeds: *feeds\n",
		"field aliases": "    feeds:\n      <<: {enabled: &names [psbl, uribl], spamhaus_dqs_key_file: &keypath /etc/csm/dqs.key}\n" +
			"      enabled: *names\n      spamhaus_dqs_key_file: *keypath\n",
		"merged": "    feeds:\n      <<: {enabled: [psbl, uribl], spamhaus_dqs_key_file: /etc/csm/dqs.key}\n",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := loadAntispam(t, "    enabled: true\n"+body)
			if err != nil {
				t.Fatal(err)
			}
			got := cfg.EmailProtection.Antispam.Feeds
			if !slices.Equal(got.Enabled, []string{"psbl", "uribl"}) || got.SpamhausDQSKeyFile != "/etc/csm/dqs.key" {
				t.Fatalf("feeds = %+v", got)
			}
		})
	}
	for _, body := range []string{
		"",
		"    feeds: null\n",
		"    feeds:\n      enabled: null\n      spamhaus_dqs_key_file: null\n",
		"    feeds:\n      enabled: &unset null\n      spamhaus_dqs_key_file: *unset\n",
	} {
		cfg, err := loadAntispam(t, "    enabled: true\n"+body)
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.EmailProtection.Antispam.Feeds; len(got.Enabled) != 0 || got.SpamhausDQSKeyFile != "" {
			t.Fatalf("expected empty feeds, got %+v", got)
		}
	}
}

func TestAntispamFeedTypesInFragments(t *testing.T) {
	for name, body := range map[string]string{
		"null name":    "enabled: [psbl, null]",
		"boolean path": "spamhaus_dqs_key_file: false",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			fragment := "email_protection:\n  antispam:\n    feeds:\n      " + body + "\n"
			must(t, os.WriteFile(filepath.Join(dir, "20-feeds.yaml"), []byte(fragment), 0o600))
			_, err := LoadBytesWithDir([]byte("email_protection:\n  antispam:\n    enabled: false\n"), dir)
			if err == nil || !strings.Contains(err.Error(), "email_protection.antispam.feeds") {
				t.Fatalf("expected a feed type error, got %v", err)
			}
		})
	}
}
