package intel

import (
	"testing"

	"github.com/pidginhost/csm/internal/mailfwd/inventory"
)

// Real-shape exim_mainlog deferral lines. IPs use RFC 5737 documentation
// ranges: 198.51.100.0/24 stands in for the server's outbound IP, 203.0.113.0/24
// for the remote MX.
const (
	yahooTSS04 = `2026-06-07 10:15:23 1uXyZ1-000ABC-2A == user@yahoo.com R=dkim_lookuphost T=remote_smtp defer (-46) H=mta7.am0.yahoodns.net [203.0.113.40]: SMTP error from remote mail server after end of data: 421 4.7.0 [TSS04] Messages from 198.51.100.7 temporarily deferred due to user complaints`

	gmailRate = `2026-06-07 11:02:55 1uXz00-000DEF-9C == someone@gmail.com R=dkim_lookuphost T=remote_smtp defer (-53) H=gmail-smtp-in.l.google.com [203.0.113.41]: SMTP error from remote mail server after end of data: 421-4.7.28 [198.51.100.7      15] Our system has detected an unusual rate of unsolicited mail`

	spamhausBlock = `2026-06-07 09:30:01 1uXw11-000AAA-1B == contact@partner.example R=dkim_lookuphost T=remote_smtp defer (-1) H=mx.partner.example [203.0.113.99]: SMTP error from remote mail server after RCPT TO: 421 4.7.1 Service unavailable; client host [198.51.100.8] blocked using zen.spamhaus.org`

	// Non-deferral lines that must never be parsed as deferrals.
	deliveryLine = `2026-06-07 10:00:00 1uXa00-000111-22 => user@example.com R=dnslookup T=remote_smtp H=mx.example.com [203.0.113.1]`
	arrivalLine  = `2026-06-07 10:00:00 1uXb00-000222-33 <= sender@local.example H=localhost [127.0.0.1] P=esmtp S=1234`
	failureLine  = `2026-06-07 10:00:00 1uXc00-000333-44 ** nobody@nx.example R=dnslookup T=remote_smtp: host mx.nx.example [203.0.113.2]: 550 No such user`
)

func TestParseDeferralLineYahoo(t *testing.T) {
	d, ok := parseDeferralLine(yahooTSS04)
	if !ok {
		t.Fatal("yahoo TSS04 line not parsed as a deferral")
	}
	if d.Recipient != "user@yahoo.com" {
		t.Errorf("recipient = %q, want user@yahoo.com", d.Recipient)
	}
	if d.Domain != "yahoo.com" {
		t.Errorf("domain = %q, want yahoo.com", d.Domain)
	}
	if d.Provider != inventory.ProviderYahoo {
		t.Errorf("provider = %q, want yahoo", d.Provider)
	}
	if d.RemoteHost != "mta7.am0.yahoodns.net" {
		t.Errorf("remote host = %q", d.RemoteHost)
	}
	if d.RemoteIP != "203.0.113.40" {
		t.Errorf("remote ip = %q, want 203.0.113.40", d.RemoteIP)
	}
	if d.OutboundIP != "198.51.100.7" {
		t.Errorf("outbound ip = %q, want 198.51.100.7 (the throttled sender)", d.OutboundIP)
	}
	if d.SMTPCode != "421" {
		t.Errorf("smtp code = %q, want 421", d.SMTPCode)
	}
	if d.ReasonCode != "TSS04" {
		t.Errorf("reason code = %q, want TSS04", d.ReasonCode)
	}
	if d.Time.IsZero() {
		t.Error("timestamp not parsed")
	}
}

func TestParseDeferralLineGmail(t *testing.T) {
	d, ok := parseDeferralLine(gmailRate)
	if !ok {
		t.Fatal("gmail rate line not parsed as a deferral")
	}
	if d.Provider != inventory.ProviderGmail {
		t.Errorf("provider = %q, want gmail", d.Provider)
	}
	if d.RemoteIP != "203.0.113.41" {
		t.Errorf("remote ip = %q, want 203.0.113.41", d.RemoteIP)
	}
	if d.OutboundIP != "198.51.100.7" {
		t.Errorf("outbound ip = %q, want 198.51.100.7 (bracketed sender, not the MX)", d.OutboundIP)
	}
	if d.SMTPCode != "421" {
		t.Errorf("smtp code = %q, want 421", d.SMTPCode)
	}
	// No bracketed [CODE]; the keyword classifier should label the rate limit.
	if d.ReasonCode != "rate_limit" {
		t.Errorf("reason = %q, want rate_limit", d.ReasonCode)
	}
}

func TestParseDeferralLineSpamhaus(t *testing.T) {
	d, ok := parseDeferralLine(spamhausBlock)
	if !ok {
		t.Fatal("spamhaus line not parsed as a deferral")
	}
	if d.Provider != inventory.ProviderExternal {
		t.Errorf("provider = %q, want external", d.Provider)
	}
	if d.RemoteIP != "203.0.113.99" {
		t.Errorf("remote ip = %q, want 203.0.113.99", d.RemoteIP)
	}
	if d.OutboundIP != "198.51.100.8" {
		t.Errorf("outbound ip = %q, want 198.51.100.8 (blocked client host)", d.OutboundIP)
	}
	if d.ReasonCode != "spamhaus" {
		t.Errorf("reason = %q, want spamhaus", d.ReasonCode)
	}
}

func TestParseDeferralLineRejectsNonDeferrals(t *testing.T) {
	for name, line := range map[string]string{
		"delivery":  deliveryLine,
		"arrival":   arrivalLine,
		"failure":   failureLine,
		"blank":     "",
		"garbage":   "not a log line at all",
		"truncated": "2026-06-07 10:00:00 1uXd00-000444-55 ==",
	} {
		if _, ok := parseDeferralLine(line); ok {
			t.Errorf("%s line was wrongly parsed as a deferral", name)
		}
	}
}

func TestBuildReportAggregatesProvidersAndIPs(t *testing.T) {
	lines := []string{
		yahooTSS04,    // yahoo, outbound .7, TSS04
		yahooTSS04,    // yahoo, outbound .7, TSS04 (repeat)
		gmailRate,     // gmail, outbound .7, rate_limit
		spamhausBlock, // external, outbound .8, spamhaus
		deliveryLine,  // ignored
	}
	rep := BuildReport(lines)

	if rep.Deferrals != 4 {
		t.Fatalf("deferrals = %d, want 4 (delivery line ignored)", rep.Deferrals)
	}

	// Providers sorted by deferral count desc: yahoo(2) first.
	if len(rep.Providers) != 3 {
		t.Fatalf("provider rollups = %d, want 3", len(rep.Providers))
	}
	if rep.Providers[0].Provider != "yahoo" || rep.Providers[0].Deferrals != 2 {
		t.Errorf("top provider = %+v, want yahoo x2", rep.Providers[0])
	}
	if len(rep.Providers[0].Reasons) != 1 || rep.Providers[0].Reasons[0].Code != "TSS04" || rep.Providers[0].Reasons[0].Count != 2 {
		t.Errorf("yahoo reasons = %+v, want TSS04 x2", rep.Providers[0].Reasons)
	}

	// Outbound IPs: .7 has 3 deferrals (2 yahoo + 1 gmail), .8 has 1.
	if len(rep.OutboundIPs) != 2 {
		t.Fatalf("outbound ip rollups = %d, want 2", len(rep.OutboundIPs))
	}
	top := rep.OutboundIPs[0]
	if top.IP != "198.51.100.7" || top.Deferrals != 3 {
		t.Errorf("top outbound ip = %+v, want 198.51.100.7 x3", top)
	}
	// .7 is deferred by two providers (yahoo + gmail).
	if len(top.Providers) != 2 {
		t.Errorf("top ip providers = %+v, want 2 distinct", top.Providers)
	}
}

func TestBuildReportEmpty(t *testing.T) {
	rep := BuildReport(nil)
	if rep.Deferrals != 0 {
		t.Errorf("deferrals = %d, want 0", rep.Deferrals)
	}
	if rep.Providers == nil || rep.OutboundIPs == nil {
		t.Error("rollups must be non-nil empty slices, not nil")
	}
}
