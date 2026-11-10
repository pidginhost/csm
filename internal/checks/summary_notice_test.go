package checks

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// The summary set reports applied automatic responses and observations that
// never act. A check that can block on its own belongs to the outcome rule,
// not to this list.
func TestSummaryRegistryChecks(t *testing.T) {
	want := []string{
		"auto_block", "challenge_route",
		"email_php_form_relay_observed", "email_php_relay_action_dry_run", "email_php_relay_rate_limit_hit",
		"mail_bruteforce_suspected",
	}
	var got []string
	for _, c := range checkRegistry {
		if !c.Summary {
			continue
		}
		got = append(got, c.Name)
		switch c.CorrelationReason {
		case reasonResponse:
		case reasonAttackerSide:
			if c.Response.Block != BlockNever {
				t.Errorf("%s is summary class but can block its source", c.Name)
			}
		default:
			t.Errorf("%s is summary class with reason %q", c.Name, c.CorrelationReason)
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("summary checks = %v, want %v", got, want)
	}
}

// Runs the registry policy the checks package installs, through the alert
// split every dispatch uses.
func TestSplitByClassSummaryNotices(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	summary := []alert.Finding{
		{Check: "auto_block", Severity: alert.Critical, Message: "AUTO-BLOCK: 203.0.113.50 blocked (expires in 24h0m0s)", SourceIP: "203.0.113.50"},
		{Check: "auto_block", Severity: alert.Critical, Message: "AUTO-PERMBLOCK: 203.0.113.50 promoted to permanent block (4 temp blocks)", SourceIP: "203.0.113.50"},
		{Check: "auto_block", Severity: alert.Critical, Message: "AUTO-BLOCK-SUBNET: 198.51.100.0/24 blocked"},
		{Check: "auto_block", Severity: alert.Critical, Message: "AUTO-NETBLOCK: 192.0.2.0/24 blocked (5 IPs from same subnet)"},
		{Check: "auto_block", Severity: alert.Warning, Message: "AUTO-BLOCK [dry-run]: 203.0.113.51 would be blocked (expires in 24h0m0s)", SourceIP: "203.0.113.51"},
		{Check: "auto_block", Severity: alert.Warning, Message: "AUTO-NETBLOCK [dry-run]: 192.0.2.0/24 would be blocked (5 IPs from same subnet)"},
		{Check: "challenge_route", Severity: alert.Warning, Message: "CHALLENGE: 203.0.113.52 sent to PoW challenge (expires in 30m0s)"},
		{Check: "mail_bruteforce_suspected", Severity: alert.High, Message: "Suspected IMAP password spray from 203.0.113.53: failed logins on 4 mailboxes it has no trusted login for (observe mode, not blocked)", SourceIP: "203.0.113.53"},
		{Check: "mail_bruteforce_suspected", Severity: alert.High, Message: "Suspected mail misconfiguration from 203.0.113.54: 12 failed auths in 10m0s from an established good source (not auto-blocked)", SourceIP: "203.0.113.54"},
		{Check: "email_php_relay_rate_limit_hit", Severity: alert.Warning, Message: "AutoFreeze rate limit deferred 2 of 5 freezes for example.com:/home/example/public_html/mail.php"},
		{Check: "email_php_relay_action_dry_run", Severity: alert.Warning, Message: "AutoFreeze dry-run: would freeze 5 msgs from example.com:/home/example/public_html/mail.php"},
		{Check: "auto_block", Severity: alert.Warning, Message: admission.AppliedSummaryMessage, Details: "events=3 first=2026-01-02T10:00:00Z last=2026-01-02T10:05:00Z"},
	}
	immediate := []alert.Finding{
		{Check: "auto_block", Severity: alert.Warning, Message: "Firewall action accounting unavailable; scan blocks deferred", DedupKey: "accounting"},
		{Check: "auto_block", Severity: alert.Warning, Message: "Block accounting unavailable; mail spray blocks deferred", DedupKey: "spray_accounting"},
		{Check: "auto_block", Severity: alert.Warning, Message: "Auto-block rate limit reached, 3 IPs queued for retry, 0 dropped", DedupKey: "rate_limit"},
		{Check: "auto_block", Severity: alert.Warning, Message: "Auto-block rate limit reached, 3 IPs queued for retry, 2 dropped", DedupKey: "rate_limit_dropped"},
		{Check: "auto_block", Severity: alert.Warning, Message: "Auto-block pending queue full, 3 IPs queued for retry, 2 dropped", DedupKey: "pending_dropped"},
		{Check: "auto_response", Severity: alert.Critical, Message: "AUTO-QUARANTINE failed for /home/example/public_html/shell.php"},
		{Check: "auto_response_paused", Severity: alert.Warning, Message: "Automatic file response paused", DedupKey: "failures"},
		{Check: "email_php_relay_action_failed", Severity: alert.High, Message: "AutoFreeze failed for example.com:/home/example/public_html/mail.php"},
		{Check: "email_php_relay_action_skipped", Severity: alert.Warning, Message: "AutoFreeze skipped for example.com:/home/example/public_html/mail.php"},
		{Check: "auto_block", Severity: alert.Critical, Message: "AUTO-BLOCK: 203.0.113.55 blocked (expires in 24h0m0s)", SourceIP: "203.0.113.55",
			Details: "Reason: scanner (warning: " + firewall.CloudflareCoverageWarning + ")"},
		{Check: "auto_response_withheld", Severity: alert.Critical, Message: "Critical automatic response withheld"},
		{Check: "auto_block", Severity: alert.Warning, Message: "Dry-run capacity forecast: 3 responses passed modelled capacity checks"},
	}
	gotImmediate, gotSummary := alert.SplitByClass(cfg, append(append([]alert.Finding(nil), summary...), immediate...))
	if got, want := classKeys(gotSummary), classKeys(summary); !slices.Equal(got, want) {
		t.Errorf("summary = %v, want %v", got, want)
	}
	if got, want := classKeys(gotImmediate), classKeys(immediate); !slices.Equal(got, want) {
		t.Errorf("immediate = %v, want %v", got, want)
	}
}

// writeCloudflareRanges stands in for the firewall's cached Cloudflare
// allow list, with documentation ranges in place of the real ones.
func writeCloudflareRanges(t *testing.T, statePath string) {
	t.Helper()
	dir := filepath.Join(statePath, "firewall")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cf_whitelist.txt"), []byte("# ipv4\n203.0.113.0/24\n# ipv6\n2001:db8:cf::/48\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A block of an address in a Cloudflare allow range leaves TCP 80/443 open,
// so it does not handle that address's web traffic, whether the block is a
// same-batch notice or blocked state. Its notice stays immediate, and the
// block still answers the address's non-web attacks.
func TestSplitByClassCloudflareCoveredBlock(t *testing.T) {
	previous := alert.BlockedIPsFunc
	alert.BlockedIPsFunc = nil
	t.Cleanup(func() { alert.BlockedIPsFunc = previous })

	t.Run("same-batch block", func(t *testing.T) {
		cfg := &config.Config{StatePath: t.TempDir()}
		writeCloudflareRanges(t, cfg.StatePath)
		notice := alert.Finding{Check: "auto_block", Severity: alert.Critical, SourceIP: "203.0.113.60",
			Message: "AUTO-BLOCK: 203.0.113.60 blocked (expires in 24h0m0s)",
			Details: "Reason: wp brute force (warning: " + firewall.CloudflareCoverageWarning + ")"}
		web := alert.Finding{Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.60", Message: "WordPress login brute force from 203.0.113.60"}
		mail := alert.Finding{Check: "smtp_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.60", Message: "SMTP brute force from 203.0.113.60"}
		immediate, summary := alert.SplitByClass(cfg, []alert.Finding{notice, web, mail})
		if got, want := classKeys(immediate), classKeys([]alert.Finding{notice, web}); !slices.Equal(got, want) {
			t.Errorf("immediate = %v, want %v", got, want)
		}
		if got, want := classKeys(summary), classKeys([]alert.Finding{mail}); !slices.Equal(got, want) {
			t.Errorf("summary = %v, want %v", got, want)
		}
	})

	t.Run("blocked state", func(t *testing.T) {
		cfg := &config.Config{StatePath: t.TempDir()}
		writeCloudflareRanges(t, cfg.StatePath)
		if err := os.WriteFile(filepath.Join(cfg.StatePath, "blocked_ips.json"), []byte(`{"ips":[
			{"ip":"203.0.113.61","expires_at":"2099-01-01T00:00:00Z"},
			{"ip":"2001:db8:cf::61","expires_at":"2099-01-01T00:00:00Z"},
			{"ip":"198.51.100.61","expires_at":"2099-01-01T00:00:00Z"}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		scanner := alert.Finding{Check: "http_scanner_profile", Severity: alert.High, SourceIP: "203.0.113.61", Message: "URL scanner profile from 203.0.113.61"}
		reputation := alert.Finding{Check: "ip_reputation", Severity: alert.High, SourceIP: "203.0.113.61", Message: "Known malicious IP accessing server: 203.0.113.61"}
		spoof := alert.Finding{Check: "http_ua_spoof", Severity: alert.Critical, SourceIP: "2001:db8:cf::61", Message: "User-Agent spoof from 2001:db8:cf::61"}
		ftp := alert.Finding{Check: "ftp_bruteforce", Severity: alert.High, SourceIP: "203.0.113.61", Message: "FTP brute force from 203.0.113.61"}
		uncovered := alert.Finding{Check: "http_scanner_profile", Severity: alert.High, SourceIP: "198.51.100.61", Message: "URL scanner profile from 198.51.100.61"}
		immediate, summary := alert.SplitByClass(cfg, []alert.Finding{scanner, reputation, spoof, ftp, uncovered})
		if got, want := classKeys(immediate), classKeys([]alert.Finding{scanner, reputation, spoof}); !slices.Equal(got, want) {
			t.Errorf("immediate = %v, want %v", got, want)
		}
		if got, want := classKeys(summary), classKeys([]alert.Finding{ftp, uncovered}); !slices.Equal(got, want) {
			t.Errorf("summary = %v, want %v", got, want)
		}
	})
}

func classKeys(findings []alert.Finding) []string {
	keys := make([]string, 0, len(findings))
	for _, f := range findings {
		keys = append(keys, f.Key())
	}
	return keys
}

func TestCloudflareCoveredRawWAFObservationsStayImmediate(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	writeCloudflareRanges(t, cfg.StatePath)
	for _, check := range []string{"modsec_warning_realtime", "modsec_block_realtime", "modsec_low_confidence_burst"} {
		t.Run(check, func(t *testing.T) {
			finding := alert.Finding{Check: check, Severity: alert.High, SourceIP: "203.0.113.60"}
			block := alert.Finding{Check: "auto_block", Severity: alert.Critical, Message: "AUTO-BLOCK: 203.0.113.60 blocked"}
			immediate, summary := alert.SplitByClass(cfg, []alert.Finding{finding, block})
			if !slices.Equal(classKeys(immediate), classKeys([]alert.Finding{finding})) || !slices.Equal(classKeys(summary), classKeys([]alert.Finding{block})) {
				t.Fatalf("immediate=%v summary=%v; a firewall block leaves this HTTP source reachable", immediate, summary)
			}
			finding.SourceIP = "198.51.100.60"
			if !IPResponseAnswersFinding(cfg, finding, true) {
				t.Fatal("a block outside Cloudflare coverage must still handle the observation")
			}
		})
	}
}
