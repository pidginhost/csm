package checks

import (
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The summary set reports applied automatic responses and observations that
// never act. A check that can block on its own belongs to the outcome rule,
// not to this list.
func TestSummaryRegistryChecks(t *testing.T) {
	want := []string{
		"auto_block", "challenge_route", "db_spam_cleaned",
		"email_php_relay_action_dry_run", "email_php_relay_rate_limit_hit",
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
		{Check: "db_spam_cleaned", Severity: alert.High, Message: "Cleaned spam links from 3 posts in example_wp (account: example)"},
		{Check: "email_php_relay_rate_limit_hit", Severity: alert.Warning, Message: "AutoFreeze rate limit deferred 2 of 5 freezes for example.com:/home/example/public_html/mail.php"},
		{Check: "email_php_relay_action_dry_run", Severity: alert.Warning, Message: "AutoFreeze dry-run: would freeze 5 msgs from example.com:/home/example/public_html/mail.php"},
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
	}
	gotImmediate, gotSummary := alert.SplitByClass(cfg, append(append([]alert.Finding(nil), summary...), immediate...))
	if got, want := classKeys(gotSummary), classKeys(summary); !slices.Equal(got, want) {
		t.Errorf("summary = %v, want %v", got, want)
	}
	if got, want := classKeys(gotImmediate), classKeys(immediate); !slices.Equal(got, want) {
		t.Errorf("immediate = %v, want %v", got, want)
	}
}

func classKeys(findings []alert.Finding) []string {
	keys := make([]string, 0, len(findings))
	for _, f := range findings {
		keys = append(keys, f.Key())
	}
	return keys
}
