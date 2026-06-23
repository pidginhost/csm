package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

type blockDigestTestBlocker struct {
	blocked map[string]bool
}

func (b *blockDigestTestBlocker) BlockIP(ip string, _ string, _ time.Duration) error {
	b.blocked[ip] = true
	return nil
}

func (b *blockDigestTestBlocker) UnblockIP(ip string) error {
	delete(b.blocked, ip)
	return nil
}

func (b *blockDigestTestBlocker) IsBlocked(ip string) bool {
	return b.blocked[ip]
}

func TestObserveBlocksFeedsCollector(t *testing.T) {
	d := &Daemon{}
	d.blockDigest = blockdigest.New(blockdigest.Options{
		Countries: nil, SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now:       func() time.Time { return time.Unix(0, 0) },
		CountryOf: func(string) string { return "RO" },
	})
	actions := []alert.Finding{
		{Check: "auto_block", Severity: alert.Critical,
			Message:   "AUTO-BLOCK: 203.0.113.20 blocked (expires in 24h)",
			Details:   "Reason: rule escalation: 5+ denies",
			Timestamp: time.Unix(0, 0)},
		{Check: "auto_block", Severity: alert.Critical, // PERMBLOCK: no Details -> skipped
			Message:   "AUTO-PERMBLOCK: 203.0.113.20 promoted to permanent block (4 temp blocks)",
			Timestamp: time.Unix(0, 0)},
		{Check: "wp_login_bruteforce", Severity: alert.Critical, // not auto_block -> skipped
			Message: "noise", Timestamp: time.Unix(0, 0)},
	}
	d.observeBlocks(actions)
	dg := d.blockDigest.Drain()
	if dg.Total != 1 {
		t.Fatalf("Total = %d, want 1 (only the real AUTO-BLOCK)", dg.Total)
	}
	if dg.Records[0].IP != "203.0.113.20" {
		t.Errorf("IP = %q", dg.Records[0].IP)
	}
	if dg.Records[0].Bucket != blockdigest.BucketAttacker {
		t.Errorf("bucket = %s, want attacker", dg.Records[0].Bucket)
	}
}

func TestObserveBlocksCategorizesWAFAttackerBlock(t *testing.T) {
	d := &Daemon{}
	d.blockDigest = blockdigest.New(blockdigest.Options{
		Countries: nil, SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now:       func() time.Time { return time.Unix(0, 0) },
		CountryOf: func(string) string { return "RO" },
	})
	d.observeBlocks([]alert.Finding{{
		Check:     "auto_block",
		Severity:  alert.Critical,
		Message:   "AUTO-BLOCK: 203.0.113.55 blocked (expires in 24h)",
		Details:   "Reason: WAF blocking high-volume attacker: 203.0.113.55 (42 blocked requests)",
		Timestamp: time.Unix(0, 0),
	}})

	dg := d.blockDigest.Drain()
	if dg.Total != 1 || dg.CustomerCount != 0 || dg.AttackerCount != 1 {
		t.Fatalf("digest counts = total:%d customer:%d attacker:%d, want 1/0/1", dg.Total, dg.CustomerCount, dg.AttackerCount)
	}
	if dg.ByCategory["modsec"] != 1 {
		t.Fatalf("ByCategory[modsec] = %d, want 1", dg.ByCategory["modsec"])
	}
	if len(dg.Records) != 1 || dg.Records[0].Bucket != blockdigest.BucketAttacker || dg.Records[0].Category != "modsec" {
		t.Fatalf("record = %+v, want attacker modsec", dg.Records)
	}
}

func TestObserveBlocksNilCollectorIsNoop(t *testing.T) {
	d := &Daemon{} // blockDigest nil (feature disabled)
	d.observeBlocks([]alert.Finding{{Check: "auto_block", Severity: alert.Critical,
		Details: "Reason: x", Message: "AUTO-BLOCK: 1.2.3.4 blocked"}})
	// must not panic
}

func TestBlockDigestSinksChannelSelection(t *testing.T) {
	d := &Daemon{}
	mk := func(channel string, email, webhook bool) *config.Config {
		c := &config.Config{}
		c.Alerts.Email.Enabled = email
		c.Alerts.Webhook.Enabled = webhook
		c.Alerts.BlockDigest.Channel = channel
		return c
	}
	// Default channel follows the live alert channel state at delivery time.
	e, w := d.blockDigestSinks(mk("", true, false))
	if e == nil || w == nil {
		t.Error("default channel should build dynamic email and webhook sinks")
	}
	// Explicit webhook overrides default channel following.
	e, w = d.blockDigestSinks(mk("webhook", true, false))
	if e != nil || w == nil {
		t.Error("explicit webhook should give webhook sink only")
	}
	// Explicit email overrides default channel following.
	e, w = d.blockDigestSinks(mk("email", true, true))
	if e == nil || w != nil {
		t.Error("explicit email should give email sink only")
	}
}

func TestBlockDigestSinksUseLiveAlertConfig(t *testing.T) {
	prevActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prevActive) })

	prevEmail := blockDigestSendEmail
	prevWebhook := blockDigestSendWebhookJSON
	t.Cleanup(func() {
		blockDigestSendEmail = prevEmail
		blockDigestSendWebhookJSON = prevWebhook
	})

	var emailCalls int
	var webhookURL string
	blockDigestSendEmail = func(*config.Config, string, string) error {
		emailCalls++
		return nil
	}
	blockDigestSendWebhookJSON = func(cfg *config.Config, _ any) error {
		webhookURL = cfg.Alerts.Webhook.URL
		return nil
	}

	startup := &config.Config{}
	startup.Alerts.BlockDigest.Channel = ""
	startup.Alerts.Email.Enabled = true
	startup.Alerts.Email.SMTP = "old-smtp.example.test:25"
	d := &Daemon{cfg: startup}

	emailSink, webhookSink := d.blockDigestSinks(startup)

	live := &config.Config{}
	live.Alerts.BlockDigest.Channel = ""
	live.Alerts.Email.Enabled = false
	live.Alerts.Webhook.Enabled = true
	live.Alerts.Webhook.URL = "https://new.example.test/hook"
	config.SetActive(live)

	if err := emailSink("subject", "body"); err != nil {
		t.Fatalf("disabled live email sink should be a no-op: %v", err)
	}
	if err := webhookSink(blockdigest.WebhookPayload{}); err != nil {
		t.Fatalf("webhook sink: %v", err)
	}
	if emailCalls != 0 {
		t.Fatalf("email sink used stale startup config; calls=%d", emailCalls)
	}
	if webhookURL != "https://new.example.test/hook" {
		t.Fatalf("webhook URL = %q, want live config URL", webhookURL)
	}
}

func TestBuildBlockDigestDisabledReturnsNil(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{}
	cfg.Alerts.BlockDigest.Enabled = false
	if c := d.buildBlockDigest(cfg); c != nil {
		t.Error("disabled block_digest should build no collector")
	}
}

func TestDispatchBatchEnrichesBlockDigestAfterHistoryAppend(t *testing.T) {
	prevActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prevActive) })

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

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

	blocker := &blockDigestTestBlocker{blocked: map[string]bool{}}
	checks.SetIPBlocker(blocker)
	t.Cleanup(func() { checks.SetIPBlocker(nil) })

	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "24h"
	cfg.AutoResponse.MaxBlocksPerHour = 100
	cfg.Thresholds.ModSecEscalationWindowMin = 10

	d := New(cfg, st, nil, "")
	d.blockDigest = blockdigest.New(blockdigest.Options{
		SendOn:       "any",
		Interval:     time.Hour,
		MinBlock:     1,
		CountryOf:    func(string) string { return "RO" },
		EnrichModSec: d.modsecEnricher(cfg),
	})

	now := time.Now()
	ip := "203.0.113.80"
	d.dispatchBatch([]alert.Finding{
		{
			Severity:  alert.High,
			Check:     "modsec_block_realtime",
			Message:   "ModSecurity blocked request: rule 900116 from 203.0.113.80 on shop.example.ro uri=/checkout",
			Details:   "Rule: 900116\nMessage: scanner\nHostname: shop.example.ro\nURI: /checkout\nRaw: x",
			SourceIP:  ip,
			Domain:    "shop.example.ro",
			Timestamp: now.Add(-time.Second),
		},
		{
			Severity:  alert.Critical,
			Check:     "modsec_csm_block_escalation",
			Message:   "CSM rule escalation: 3+ denies from 203.0.113.80 within 10m0s",
			SourceIP:  ip,
			Timestamp: now,
		},
	})

	dg := d.blockDigest.Drain()
	if dg.Total != 1 {
		t.Fatalf("digest total = %d, want 1", dg.Total)
	}
	rec := dg.Records[0]
	if len(rec.Domains) != 1 || rec.Domains[0] != "shop.example.ro" {
		t.Fatalf("digest domains = %v, want [shop.example.ro]", rec.Domains)
	}
	if len(rec.URIs) != 1 || rec.URIs[0] != "/checkout" {
		t.Fatalf("digest uris = %v, want [/checkout]", rec.URIs)
	}
}
