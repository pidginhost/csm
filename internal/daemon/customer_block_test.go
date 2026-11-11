package daemon

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/reporting"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// customerTestBlocker keeps a live view of its blocks and records each
// block's length. outcome, when set, replaces the live outcome.
type customerTestBlocker struct {
	mu      sync.Mutex
	blocked map[string]bool
	calls   []customerBlockCall
	outcome firewall.BlockOutcome
	fail    int // calls left that fail with an engine error
}

type customerBlockCall struct {
	ip  string
	ttl time.Duration
}

func (b *customerTestBlocker) BlockIP(ip, reason string, ttl time.Duration) error {
	_, err := b.BlockIPOutcome(ip, reason, ttl)
	return err
}

func (b *customerTestBlocker) BlockIPOutcome(ip, _ string, ttl time.Duration) (firewall.BlockOutcome, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, customerBlockCall{ip, ttl})
	if b.fail > 0 {
		b.fail--
		return firewall.BlockOutcomeNoop, errors.New("fixture engine busy")
	}
	if b.outcome != "" {
		return b.outcome, nil
	}
	b.blocked[ip] = true
	return firewall.BlockOutcomeLive, nil
}

func (b *customerTestBlocker) UnblockIP(ip string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.blocked, ip)
	return nil
}

func (b *customerTestBlocker) IsBlocked(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.blocked[ip]
}

type customerMail struct{ subject, body string }

// customerCapture records what the collector's sinks send.
type customerCapture struct {
	mu       sync.Mutex
	emails   []customerMail
	payloads []blockdigest.WebhookPayload
}

func (c *customerCapture) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.emails, c.payloads = nil, nil
}

func (c *customerCapture) customerEmails() []customerMail {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []customerMail
	for _, m := range c.emails {
		if strings.Contains(m.subject, "known customer") {
			out = append(out, m)
		}
	}
	return out
}

func (c *customerCapture) events(event string) []blockdigest.WebhookPayload {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []blockdigest.WebhookPayload
	for _, p := range c.payloads {
		if p.CSM.Event == event {
			out = append(out, p)
		}
	}
	return out
}

func customerBlockSetup(t *testing.T) (*Daemon, *config.Config, *customerTestBlocker, *customerCapture) {
	t.Helper()
	prevActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prevActive) })
	prevEmail, prevWebhook := blockDigestSendEmail, blockDigestSendWebhookJSON
	t.Cleanup(func() { blockDigestSendEmail, blockDigestSendWebhookJSON = prevEmail, prevWebhook })
	capture := &customerCapture{}
	blockDigestSendEmail = func(_ *config.Config, subject, body string) error {
		capture.mu.Lock()
		defer capture.mu.Unlock()
		capture.emails = append(capture.emails, customerMail{subject, body})
		return nil
	}
	blockDigestSendWebhookJSON = func(_ *config.Config, payload any) error {
		capture.mu.Lock()
		defer capture.mu.Unlock()
		capture.payloads = append(capture.payloads, payload.(blockdigest.WebhookPayload))
		return nil
	}

	sdb, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prevStore := store.Global()
	store.SetGlobal(sdb)
	t.Cleanup(func() {
		store.SetGlobal(prevStore)
		_ = sdb.Close()
	})
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	blocker := &customerTestBlocker{blocked: map[string]bool{}}
	checks.SetIPBlocker(blocker)
	t.Cleanup(func() { checks.SetIPBlocker(nil) })

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host.example.com"}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.BlockIPs = true, true
	cfg.AutoResponse.BlockExpiry = "6h"
	cfg.AutoResponse.MaxBlocksPerHour = 100
	cfg.Alerts.Email.Enabled, cfg.Alerts.Webhook.Enabled = true, true
	d := New(cfg, st, nil, "")
	d.blockDigest = d.buildBlockDigest(cfg)
	return d, cfg, blocker, capture
}

func smtpBruteFrom(ip string) alert.Finding {
	return alert.Finding{Severity: alert.Critical, Check: "smtp_bruteforce", Message: "SMTP brute force from " + ip,
		SourceIP: ip, Timestamp: time.Now()}
}

// customerLogin notes a cPanel login by alice from ip two hours ago and
// returns its rendered time.
func customerLogin(d *Daemon, ip string) string {
	at := time.Now().Add(-2 * time.Hour).Truncate(time.Minute)
	d.knownCustomers.Note(ip, knownCustomerCpanel, "alice", at, serviceLog)
	return at.In(time.Local).Format("2006-01-02 15:04 MST")
}

// Every automatic block path reports a block of a known customer at once:
// one email naming the address, the login kind, account and time, and one
// webhook event.
func TestCustomerBlockAlertEveryBlockPath(t *testing.T) {
	const ip = "203.0.113.10"
	cases := []struct {
		name      string
		prepare   func(*Daemon, *config.Config, *customerTestBlocker)
		block     func(*testing.T, *Daemon, *config.Config)
		wantCheck string
		wantText  string
	}{
		{name: "scan block in dispatch", wantCheck: "smtp_bruteforce",
			block: func(_ *testing.T, d *Daemon, _ *config.Config) { d.dispatchBatch([]alert.Finding{smtpBruteFrom(ip)}) }},
		{name: "permanent promotion in the same batch", wantCheck: "smtp_bruteforce", wantText: "promoted to permanent block",
			prepare: func(d *Daemon, cfg *config.Config, b *customerTestBlocker) {
				cfg.AutoResponse.PermBlock = true
				cfg.AutoResponse.PermBlockCount = config.MinBlockEscalationCount
				d.dispatchBatch([]alert.Finding{smtpBruteFrom(ip)})
				_ = b.UnblockIP(ip)
			},
			block: func(_ *testing.T, d *Daemon, _ *config.Config) { d.dispatchBatch([]alert.Finding{smtpBruteFrom(ip)}) }},
		{name: "periodic scan block arriving as a finding", wantCheck: "smtp_bruteforce",
			block: func(_ *testing.T, d *Daemon, cfg *config.Config) {
				// A scan runs its own auto-response and hands its blocks
				// to dispatch with the findings that caused them.
				scanned := []alert.Finding{smtpBruteFrom(ip)}
				_, blocks := checks.ChallengeThenBlock(cfg, scanned)
				d.dispatchBatch(append(scanned, blocks...))
			}},
		{name: "initial scan", wantCheck: "smtp_bruteforce",
			block: func(_ *testing.T, d *Daemon, cfg *config.Config) {
				scanned := []alert.Finding{smtpBruteFrom(ip)}
				_, blocks := checks.ChallengeThenBlock(cfg, scanned)
				d.respondToInitialScan(cfg, append(scanned, blocks...))
			}},
		{name: "challenge timeout", wantCheck: "wp_login_bruteforce",
			block: func(t *testing.T, d *Daemon, _ *config.Config) {
				// Routed while admission was not wired: no root, only the
				// finding's identity and check.
				f := alert.Finding{Severity: alert.High, Check: "wp_login_bruteforce", Message: "WordPress brute force from " + ip, SourceIP: ip, Timestamp: time.Now()}
				d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
				d.ipList.AddWithRoot(ip, f.Message, -time.Minute, alert.FindingID(f), f.Check, admission.Evidence{})
				d.escalateExpiredChallenges(time.Hour)
			}},
		{name: "central intelligence", wantCheck: "smtp_bruteforce",
			block: func(t *testing.T, d *Daemon, _ *config.Config) {
				store := centralStoreWith(t, []reporting.ScoredEntry{{IP: ip, Score: 95, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Now().UTC()}})
				action, ok := d.planCentralAction(store, reporting.ActionBlockIfLocalCorroborated, 80, func(string) bool { return false }, smtpBruteFrom(ip))
				if !ok || action.decision != reporting.DecisionBlock {
					t.Fatalf("central plan = %+v (%v), want a block", action, ok)
				}
				if err := d.performCentralAction(action); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "incident", wantCheck: "mail_bruteforce",
			block: func(t *testing.T, d *Daemon, _ *config.Config) {
				root := incident.PreparedRoot{Finding: alert.Finding{Severity: alert.Critical, Check: "mail_bruteforce",
					Message: "Mail auth brute force from " + ip, SourceIP: ip, Timestamp: time.Now()}}
				if _, err := d.applyIncidentBlock(ip, "incident: account spray", time.Hour, "", root, admission.EntryIncidentSpray); err != nil {
					t.Fatal(err)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, cfg, blocker, capture := customerBlockSetup(t)
			when := customerLogin(d, ip)
			if tc.prepare != nil {
				tc.prepare(d, cfg, blocker)
			}
			capture.reset()
			tc.block(t, d, cfg)

			if !blocker.IsBlocked(ip) {
				t.Fatalf("%s did not block %s", tc.name, ip)
			}
			mails := capture.customerEmails()
			if len(mails) != 1 {
				t.Fatalf("customer emails = %d, want 1: %+v", len(mails), mails)
			}
			body := mails[0].body
			if !strings.Contains(mails[0].subject, ip) {
				t.Fatalf("subject %q does not name %s", mails[0].subject, ip)
			}
			if want := "Known customer: " + ip + " cpanel login as alice at " + when; !strings.Contains(body, want) {
				t.Fatalf("body has no %q:\n%s", want, body)
			}
			if n := strings.Count(body, "Block: "); n != 1 {
				t.Fatalf("blocks listed = %d, want 1:\n%s", n, body)
			}
			if tc.wantCheck != "" && !strings.Contains(body, "Check: "+tc.wantCheck+"\n") {
				t.Fatalf("body does not name check %s:\n%s", tc.wantCheck, body)
			}
			if tc.wantText != "" && !strings.Contains(body, tc.wantText) {
				t.Fatalf("body has no %q:\n%s", tc.wantText, body)
			}
			hooks := capture.events("customer_block")
			if len(hooks) != 1 || len(hooks[0].CSM.CustomerBlocks) != 1 || hooks[0].CSM.CustomerBlocks[0].Target != ip {
				t.Fatalf("customer_block webhooks = %+v, want one naming %s", hooks, ip)
			}
		})
	}
}

// A netblock over many known customers is one message with their count and
// a few examples, not one message per customer.
func TestCustomerBlockAlertSubnetCount(t *testing.T) {
	for _, tc := range []struct{ name, message, target string }{
		{"netblock", "AUTO-NETBLOCK: 198.51.100.0/24 blocked (5 IPs from same subnet)", "198.51.100.0/24"},
		{"subnet", "AUTO-BLOCK-SUBNET: 198.51.100.0/24 blocked", "198.51.100.0/24"},
		{"mapped subnet", "AUTO-BLOCK-SUBNET: ::ffff:198.51.100.0/120 blocked", "198.51.100.0/24"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, _, capture := customerBlockSetup(t)
			at := time.Now().Add(-time.Hour)
			for i := range 200 {
				d.knownCustomers.Note(fmt.Sprintf("198.51.100.%d", i+1), knownCustomerWebmail, fmt.Sprintf("user%d@example.com", i+1), at.Add(time.Duration(i)*time.Second), serviceLog)
			}
			d.knownCustomers.Note("203.0.113.99", knownCustomerWebmail, "outside@example.com", at, serviceLog)
			d.recordAppliedBlocks([]alert.Finding{{Severity: alert.Critical, Check: "auto_block", Message: tc.message,
				Details: "Reason: mail auth spray", Timestamp: time.Now()}})

			mails := capture.customerEmails()
			if len(mails) != 1 {
				t.Fatalf("customer emails = %d, want 1", len(mails))
			}
			body := mails[0].body
			if !strings.Contains(body, "200 known customers") {
				t.Fatalf("body does not count 200 known customers:\n%s", body)
			}
			if n := strings.Count(body, " webmail login as "); n != 5 {
				t.Fatalf("examples = %d, want 5:\n%s", n, body)
			}
			if strings.Contains(body, "outside@example.com") {
				t.Fatalf("a customer outside the subnet is listed:\n%s", body)
			}
			hooks := capture.events("customer_block")
			if len(hooks) != 1 || len(hooks[0].CSM.CustomerBlocks) != 1 {
				t.Fatalf("webhooks = %+v", hooks)
			}
			b := hooks[0].CSM.CustomerBlocks[0]
			if b.Target != tc.target || len(b.Hits) != 5 || b.More != 195 {
				t.Fatalf("block = target %q, %d hits, %d more; want %s, 5, 195", b.Target, len(b.Hits), b.More, tc.target)
			}
			if b.Hits[0].IP != "198.51.100.200" {
				t.Fatalf("first example = %s, want the most recent login", b.Hits[0].IP)
			}
		})
	}
}

// One block is one message; the address staying blocked sends nothing more,
// and a new block after the first ended sends another.
func TestCustomerBlockAlertOncePerBlock(t *testing.T) {
	const ip = "203.0.113.11"
	d, _, blocker, capture := customerBlockSetup(t)
	customerLogin(d, ip)

	d.dispatchBatch([]alert.Finding{smtpBruteFrom(ip)})
	if n := len(capture.customerEmails()); n != 1 {
		t.Fatalf("customer emails after the block = %d, want 1", n)
	}
	d.dispatchBatch([]alert.Finding{smtpBruteFrom(ip)})
	if n := len(capture.customerEmails()); n != 1 {
		t.Fatalf("customer emails while still blocked = %d, want 1", n)
	}
	_ = blocker.UnblockIP(ip)
	d.dispatchBatch([]alert.Finding{smtpBruteFrom(ip)})
	if n := len(capture.customerEmails()); n != 2 {
		t.Fatalf("customer emails after a new block = %d, want 2", n)
	}
	if n := len(capture.events("customer_block")); n != 2 {
		t.Fatalf("customer_block webhooks = %d, want 2", n)
	}
}

// A scan that blocks the same address again after its block ended reports
// the same notice text, which the repeat filter has seen; the new block is
// still alerted.
func TestCustomerBlockAlertRepeatedScanBlock(t *testing.T) {
	const ip = "203.0.113.17"
	d, cfg, blocker, capture := customerBlockSetup(t)
	customerLogin(d, ip)
	scan := func() {
		scanned := []alert.Finding{smtpBruteFrom(ip)}
		_, blocks := checks.ChallengeThenBlock(cfg, scanned)
		d.dispatchBatch(append(scanned, blocks...))
	}
	scan()
	_ = blocker.UnblockIP(ip)
	scan()
	if n := len(capture.customerEmails()); n != 2 {
		t.Fatalf("customer emails = %d, want one per block", n)
	}
}

// A promotion that reaches CSM apart from its block sends its own message,
// naming the promotion.
func TestCustomerBlockAlertPromotionApart(t *testing.T) {
	const ip = "203.0.113.18"
	d, _, _, capture := customerBlockSetup(t)
	customerLogin(d, ip)
	d.recordAppliedBlocks([]alert.Finding{{Severity: alert.Critical, Check: "auto_block", SourceIP: ip, Timestamp: time.Now(),
		Message: "AUTO-PERMBLOCK: " + ip + " promoted to permanent block (4 temp blocks)"}})
	mails := capture.customerEmails()
	if len(mails) != 1 || !strings.Contains(mails[0].body, "Reason: AUTO-PERMBLOCK: "+ip+" promoted to permanent block") {
		t.Fatalf("customer emails = %+v, want one naming the promotion", mails)
	}
}

// The alert never exempts a customer: the block lands with its configured
// length and its notice stays a Critical auto_block.
func TestCustomerBlockNoExemption(t *testing.T) {
	const ip = "203.0.113.12"
	d, cfg, blocker, capture := customerBlockSetup(t)
	customerLogin(d, ip)

	d.dispatchBatch([]alert.Finding{smtpBruteFrom(ip)})

	if len(capture.customerEmails()) != 1 {
		t.Fatal("no customer alert for the block")
	}
	want := parseBlockExpiry(cfg.AutoResponse.BlockExpiry)
	if len(blocker.calls) != 1 || blocker.calls[0].ip != ip || blocker.calls[0].ttl != want {
		t.Fatalf("engine calls = %+v, want one block of %s for %s", blocker.calls, ip, want)
	}
	if !blocker.IsBlocked(ip) {
		t.Fatal("customer address not blocked")
	}
	if ips := blockedTrackerIPs(t, cfg.StatePath); len(ips) != 1 || ips[0] != ip {
		t.Fatalf("tracker = %v, want %s", ips, ip)
	}
	history, _ := d.store.ReadHistory(50, 0)
	found := false
	for _, f := range history {
		if f.Check == "auto_block" && f.Severity == alert.Critical && f.Message == fmt.Sprintf("AUTO-BLOCK: %s blocked (expires in %s)", ip, want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("history has no Critical auto_block for %s: %+v", ip, history)
	}
}

func TestCustomerBlockIgnoresUnknownAndDryRun(t *testing.T) {
	t.Run("unknown address", func(t *testing.T) {
		d, _, blocker, capture := customerBlockSetup(t)
		customerLogin(d, "203.0.113.13")
		d.dispatchBatch([]alert.Finding{smtpBruteFrom("203.0.113.14")})
		if !blocker.IsBlocked("203.0.113.14") {
			t.Fatal("unknown address not blocked")
		}
		if mails := capture.customerEmails(); len(mails) != 0 {
			t.Fatalf("customer emails = %+v, want none", mails)
		}
	})
	t.Run("dry run", func(t *testing.T) {
		d, _, blocker, capture := customerBlockSetup(t)
		blocker.outcome = firewall.BlockOutcomeDryRun
		customerLogin(d, "203.0.113.15")
		d.dispatchBatch([]alert.Finding{smtpBruteFrom("203.0.113.15")})
		if len(blocker.calls) != 1 || blocker.IsBlocked("203.0.113.15") {
			t.Fatalf("dry run calls = %+v, want one call and no block", blocker.calls)
		}
		if mails := capture.customerEmails(); len(mails) != 0 {
			t.Fatalf("customer emails = %+v, want none for a dry-run verdict", mails)
		}
		if hooks := capture.events("customer_block"); len(hooks) != 0 {
			t.Fatalf("customer_block webhooks = %+v, want none", hooks)
		}
	})
}

// Observe-mode and dry-run verdicts on known customers are listed in the
// daily summary; the established-source advisory of the same check is not a
// verdict.
func TestWouldBlockCustomerInSummary(t *testing.T) {
	d, cfg, blocker, capture := customerBlockSetup(t)
	alert.SetSummaryHook(d.noteSummary)
	t.Cleanup(func() { alert.SetSummaryHook(nil) })
	blocker.outcome = firewall.BlockOutcomeDryRun
	at := time.Now().Add(-time.Hour)
	for _, ip := range []string{"203.0.113.30", "203.0.113.31", "203.0.113.32", "198.51.100.40"} {
		d.knownCustomers.Note(ip, knownCustomerIMAP, "office@example.com", at, syslogFed)
	}

	d.dispatchBatch([]alert.Finding{smtpBruteFrom("203.0.113.30")})
	d.noteSummary(cfg, []alert.Finding{
		{Severity: alert.High, Check: "mail_bruteforce_suspected", SourceIP: "203.0.113.31",
			Message: "Suspected IMAP/POP password spray from 203.0.113.31: failed logins on 3 mailboxes it has no trusted login for (observe mode, not blocked)"},
		{Severity: alert.High, Check: "mail_bruteforce_suspected", SourceIP: "203.0.113.32",
			Message: "Suspected mail misconfiguration from 203.0.113.32: 5 failed auths in 10m0s from an established good source (not auto-blocked)"},
		{Severity: alert.Warning, Check: "auto_block", Message: "AUTO-BLOCK-SUBNET [dry-run]: 198.51.100.0/24 would be blocked",
			Details: "Reason: mail auth spray"},
		{Severity: alert.Warning, Check: "auto_block", Message: "AUTO-BLOCK [dry-run]: 203.0.113.33 would be blocked (expires in 6h0m0s)",
			Details: "Reason: fixture", SourceIP: "203.0.113.33"},
	})
	if mails := capture.customerEmails(); len(mails) != 0 {
		t.Fatalf("would-block verdicts emailed at once: %+v", mails)
	}
	s := sendSummary(t, d, capture, time.Now().Add(25*time.Hour))
	var targets []string
	for _, b := range s.WouldBlock {
		targets = append(targets, b.Target)
	}
	if got, want := strings.Join(targets, ","), "203.0.113.30,203.0.113.31,198.51.100.0/24"; got != want {
		t.Fatalf("would-block targets = %s, want %s", got, want)
	}
	if b := s.WouldBlock[0]; b.Check != "smtp_bruteforce" || b.Reason != "SMTP brute force from 203.0.113.30" || len(b.Hits) != 1 || b.Hits[0].Kind != knownCustomerIMAP {
		t.Fatalf("dry-run verdict = %+v", b)
	}
	if b := s.WouldBlock[1]; b.Check != "mail_bruteforce_suspected" || !strings.Contains(b.Reason, "observe mode") {
		t.Fatalf("observe verdict = %+v", b)
	}

	for i := range 55 {
		ip := fmt.Sprintf("192.0.2.%d", i+1)
		d.knownCustomers.Note(ip, knownCustomerPOP, "", at, syslogFed)
		d.noteSummary(cfg, []alert.Finding{{Severity: alert.Warning, Check: "auto_block", SourceIP: ip,
			Message: "AUTO-BLOCK [dry-run]: " + ip + " would be blocked (expires in 6h0m0s)", Details: "Reason: fixture"}})
	}
	capture.reset()
	s = sendSummary(t, d, capture, time.Now().Add(49*time.Hour))
	if len(s.WouldBlock) != 50 || s.WouldBlockMore != 5 {
		t.Fatalf("would-block = %d listed + %d more, want 50 + 5", len(s.WouldBlock), s.WouldBlockMore)
	}
}

// A block caused by the customer login itself, a mail account compromise or
// an FTP login after brute force from the same address (or IPv6 /64) and
// account, sends no customer alert: the Critical finding already names that
// login. A block of the address for another check, or a compromise of
// another mailbox or through another login kind, still alerts.
func TestCustomerBlockSkipsItsOwnCauseLogin(t *testing.T) {
	compromise := func(ip, mailbox string) alert.Finding {
		return alert.Finding{Severity: alert.Critical, Check: "mail_account_compromised", SourceIP: ip, Mailbox: mailbox, Timestamp: time.Now(),
			Message: "Mail account compromise: successful login for " + mailbox + " from " + ip + " after recent auth failures"}
	}
	ftpCause := func(ip string) []alert.Finding {
		// A scan hands its blocks to dispatch with the findings that caused them.
		f := alert.Finding{Severity: alert.Critical, Check: "ftp_login_after_bruteforce", SourceIP: ip, TenantID: "Alice", Timestamp: time.Now(),
			Message: "FTP login succeeded for account alice from brute-force source " + ip + " after 9 failed attempts"}
		cause := alert.CauseOf(f)
		return []alert.Finding{f, {Severity: alert.Critical, Check: "auto_block", SourceIP: ip, Timestamp: time.Now(), Cause: &cause,
			Message: "AUTO-BLOCK: " + ip + " blocked (expires in 6h0m0s)", Details: "Reason: " + f.Message}}
	}
	imapLogin := func(mailbox string) func(*Daemon, string) {
		return func(d *Daemon, ip string) {
			d.knownCustomers.Note(ip, knownCustomerIMAP, mailbox, time.Now().Add(-time.Minute), syslogFed)
		}
	}
	for _, tc := range []struct {
		name   string
		ip     string
		login  func(*Daemon, string)
		batch  []alert.Finding
		alerts int
	}{
		{"compromise of the login", "203.0.113.20", imapLogin("office@example.com"), []alert.Finding{compromise("203.0.113.20", "Office@example.com")}, 0},
		{"compromise inside the login /64", "2001:db8:2::5", func(d *Daemon, _ string) { imapLogin("office@example.com")(d, "2001:db8:2::1") },
			[]alert.Finding{compromise("2001:db8:2::5", "office@example.com")}, 0},
		{"FTP login after brute force", "203.0.113.21", nil, ftpCause("203.0.113.21"), 0},
		{"unrelated check", "203.0.113.22", imapLogin("office@example.com"), []alert.Finding{smtpBruteFrom("203.0.113.22")}, 1},
		{"compromise of another mailbox", "203.0.113.23", imapLogin("alice@example.com"), []alert.Finding{compromise("203.0.113.23", "office@example.com")}, 1},
		{"compromise beside a webmail login", "203.0.113.24", func(d *Daemon, ip string) {
			d.knownCustomers.Note(ip, knownCustomerWebmail, "office@example.com", time.Now().Add(-time.Minute), serviceLog)
		}, []alert.Finding{compromise("203.0.113.24", "office@example.com")}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, blocker, capture := customerBlockSetup(t)
			if tc.login != nil {
				tc.login(d, tc.ip)
			}
			d.dispatchBatch(tc.batch)
			if _, ok := d.knownCustomers.Lookup(tc.ip); !ok {
				t.Fatalf("%s is not a known customer", tc.ip)
			}
			if tc.batch[0].Check != "ftp_login_after_bruteforce" && !blocker.IsBlocked(tc.ip) {
				t.Fatalf("%s not blocked", tc.ip)
			}
			if n, hooks := len(capture.customerEmails()), len(capture.events("customer_block")); n != tc.alerts || hooks != tc.alerts {
				t.Fatalf("customer emails = %d, webhooks = %d, want %d each", n, hooks, tc.alerts)
			}
		})
	}
}

// A customer alert whose email fails still reaches the operator: the next
// daily summary lists the block.
func TestCustomerBlockListedInSummaryWhenAlertFails(t *testing.T) {
	const ip = "203.0.113.19"
	d, _, blocker, capture := customerBlockSetup(t)
	when := customerLogin(d, ip)
	blockDigestSendEmail = func(_ *config.Config, subject, body string) error {
		if strings.Contains(subject, "known customer") {
			return errors.New("fixture smtp down")
		}
		capture.mu.Lock()
		defer capture.mu.Unlock()
		capture.emails = append(capture.emails, customerMail{subject, body})
		return nil
	}
	d.dispatchBatch([]alert.Finding{smtpBruteFrom(ip)})
	if !blocker.IsBlocked(ip) || len(capture.customerEmails()) != 0 {
		t.Fatalf("blocked=%v customer emails=%+v, want a block whose alert email failed", blocker.IsBlocked(ip), capture.customerEmails())
	}
	s := sendSummary(t, d, capture, time.Now().Add(25*time.Hour))
	if len(s.CustomerBlocks) != 1 || s.CustomerBlocks[0].Target != ip || s.CustomerBlocks[0].Check != "smtp_bruteforce" {
		t.Fatalf("summary customer blocks = %+v, want the block of %s", s.CustomerBlocks, ip)
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.emails) != 1 || !strings.Contains(capture.emails[0].body, "Known customer: "+ip+" cpanel login as alice at "+when) {
		t.Fatalf("summary emails = %+v, want one naming the customer", capture.emails)
	}
}

func sendSummary(t *testing.T, d *Daemon, capture *customerCapture, at time.Time) blockdigest.Summary {
	t.Helper()
	d.blockDigest.SendDue(at)
	hooks := capture.events("daily_summary")
	if len(hooks) != 1 || hooks[0].CSM.Summary == nil {
		t.Fatalf("daily summary webhooks = %+v", hooks)
	}
	return *hooks[0].CSM.Summary
}

// A phpanel webhook takes signed findings only: the customer alert creates
// no job there and counts no delivery, while email still goes out.
func TestCustomerBlockWebhookSkipsPhpanel(t *testing.T) {
	for _, hook := range []string{"phpanel", "generic"} {
		t.Run(hook, func(t *testing.T) {
			d, cfg, _, capture := customerBlockSetup(t)
			// The delivery policy reads the live config.
			cfg.Alerts.Webhook.Type = hook

			entered, release := make(chan struct{}), make(chan struct{})
			blockDigestSendEmail = func(*config.Config, string, string) error {
				close(entered)
				<-release
				return nil
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				d.blockDigest.AlertCustomerBlocks([]blockdigest.CustomerBlock{{Target: "203.0.113.16", Reason: "fixture",
					Hits: []blockdigest.CustomerHit{{IP: "203.0.113.16", Kind: knownCustomerCpanel, Account: "alice", At: time.Now()}}}})
			}()
			select {
			case <-entered:
			case <-done:
				t.Fatal("customer alert sent no email")
			case <-time.After(5 * time.Second):
				t.Fatal("customer alert email never started")
			}
			wantDepth := 1
			if hook == "phpanel" {
				wantDepth = 0
			}
			row := d.QueueStatuses()["block_digest.webhook"]
			close(release)
			<-done
			if row.Depth != wantDepth {
				t.Fatalf("%s customer webhook jobs waiting = %d, want %d: %+v", hook, row.Depth, wantDepth, row)
			}
			wantHooks := 1
			if hook == "phpanel" {
				wantHooks = 0
			}
			if n := len(capture.events("customer_block")); n != wantHooks {
				t.Fatalf("%s customer_block webhooks = %d, want %d", hook, n, wantHooks)
			}
			if row := d.QueueStatuses()["block_digest.webhook"]; row.DroppedTotal != 0 || row.Depth != 0 || row.InFlight != 0 {
				t.Fatalf("%s webhook row = %+v", hook, row)
			}
		})
	}
}

// The customer alert replaces the live digest notification, while watched
// blocks still reach the daily roll-up and unknown addresses still alert.
func TestCustomerBlockReplacesLiveDigest(t *testing.T) {
	for _, channel := range []string{"", "email", "webhook"} {
		t.Run(channel, func(t *testing.T) {
			d, cfg, blocker, capture := customerBlockSetup(t)
			cfg.Alerts.BlockDigest.Enabled, cfg.Alerts.BlockDigest.Live = true, true
			cfg.Alerts.BlockDigest.Channel = channel
			d.blockDigest = d.buildBlockDigest(cfg)
			const customer, unknown = "2001:db8:1::9", "203.0.113.92"
			customerLogin(d, "2001:db8:1::1")
			d.dispatchBatch([]alert.Finding{smtpBruteFrom(customer)})
			if !blocker.IsBlocked(customer) {
				t.Fatal("customer block did not apply")
			}
			if len(capture.emails) != 1 || len(capture.payloads) != 1 || capture.payloads[0].CSM.Event != "customer_block" {
				t.Fatalf("one block sent %d emails and %d webhooks, want one customer alert per channel", len(capture.emails), len(capture.payloads))
			}
			capture.reset()
			d.dispatchBatch([]alert.Finding{smtpBruteFrom(unknown)})
			wantEmails, wantHooks := 1, 1
			if channel == "email" {
				wantHooks = 0
			}
			if channel == "webhook" {
				wantEmails = 0
			}
			if len(capture.emails) != wantEmails || len(capture.events("block_live")) != wantHooks {
				t.Fatalf("unknown block sent %d emails and %d live webhooks, want %d/%d", len(capture.emails), len(capture.events("block_live")), wantEmails, wantHooks)
			}
			if dg := d.blockDigest.Drain(); dg.Total != 2 {
				t.Fatalf("watched blocks = %d, want both blocks", dg.Total)
			}
		})
	}
}

// Derived block sources already retain the originating check. Its identity
// must survive the chokepoint into the customer alert.
func TestCustomerBlockDerivedCause(t *testing.T) {
	for _, path := range []string{"central root", "central finding", "challenge root"} {
		t.Run(path, func(t *testing.T) {
			d, _, blocker, capture := customerBlockSetup(t)
			const ip = "203.0.113.93"
			customerLogin(d, ip)
			f := observedBruteForce(ip)
			root := mintedRoot(t, f)
			switch path {
			case "central root":
				if err := d.performCentralAction(centralQueuedAction{decision: reporting.DecisionBlock, ip: ip, findingID: alert.FindingID(f), root: root}); err != nil {
					t.Fatal(err)
				}
			case "central finding":
				if err := d.performCentralAction(centralQueuedAction{decision: reporting.DecisionBlock, ip: ip, rootFinding: f}); err != nil {
					t.Fatal(err)
				}
			case "challenge root":
				d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
				d.ipList.AddWithRoot(ip, "wp brute", -time.Minute, root.FindingID(), root.Check(), root)
				d.escalateExpiredChallenges(time.Hour)
			}
			if !blocker.IsBlocked(ip) {
				t.Fatal("derived block did not apply")
			}
			hooks := capture.events("customer_block")
			if len(hooks) != 1 || len(hooks[0].CSM.CustomerBlocks) != 1 || hooks[0].CSM.CustomerBlocks[0].Check != f.Check {
				t.Fatalf("customer alerts = %+v, want one naming %s", hooks, f.Check)
			}
		})
	}
}

// A rollover during customer lookup must not separate a dispatch's verdict
// list from its finding counts, or split the list across two summaries.
func TestWouldBlockSummaryRolloverKeepsBatchTogether(t *testing.T) {
	d, cfg, _, capture := customerBlockSetup(t)
	for _, ip := range []string{"203.0.113.95", "203.0.113.96"} {
		customerLogin(d, ip)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() { unblock(); <-done })
	lookups := 0
	d.knownCustomers.now = func() time.Time {
		lookups++
		if lookups == 2 {
			close(entered)
			<-release
		}
		return time.Now()
	}
	go func() {
		defer close(done)
		d.noteSummary(cfg, []alert.Finding{
			{Severity: alert.Warning, Check: "auto_block", SourceIP: "203.0.113.95", Message: "AUTO-BLOCK [dry-run]: 203.0.113.95 would be blocked"},
			{Severity: alert.Warning, Check: "auto_block", SourceIP: "203.0.113.96", Message: "AUTO-BLOCK [dry-run]: 203.0.113.96 would be blocked"},
		})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("second customer lookup did not start")
	}
	first := sendSummary(t, d, capture, time.Now().Add(25*time.Hour))
	unblock()
	<-done
	capture.reset()
	second := sendSummary(t, d, capture, time.Now().Add(49*time.Hour))
	if len(first.WouldBlock) != 0 || first.Checks["auto_block"]["WARNING"] != 0 {
		t.Fatalf("rollover sent a partial batch: %d verdicts, %d findings", len(first.WouldBlock), first.Checks["auto_block"]["WARNING"])
	}
	if len(second.WouldBlock) != 2 || second.Checks["auto_block"]["WARNING"] != 2 {
		t.Fatalf("next summary = %d verdicts, %d findings; want 2/2", len(second.WouldBlock), second.Checks["auto_block"]["WARNING"])
	}
}
