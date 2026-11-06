package daemon

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
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
		Watch: true, SendOn: "any", Interval: time.Hour, MinBlock: 1,
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
		Watch: true, SendOn: "any", Interval: time.Hour, MinBlock: 1,
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

func TestObserveBlocksIgnoresCloudflareWarningWhenClassifying(t *testing.T) {
	d := &Daemon{}
	d.blockDigest = blockdigest.New(blockdigest.Options{
		Watch: true, SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now:       func() time.Time { return time.Unix(0, 0) },
		CountryOf: func(string) string { return "RO" },
	})
	d.observeBlocks([]alert.Finding{{
		Check:     "auto_block",
		Severity:  alert.Critical,
		Message:   "AUTO-BLOCK: 203.0.113.56 blocked (expires in 24h)",
		Details:   "Reason: rule escalation: repeated denies (warning: IP is inside a Cloudflare allow range; ports 80/443 from it are still accepted)",
		Timestamp: time.Unix(0, 0),
	}})

	dg := d.blockDigest.Drain()
	if dg.Total != 1 || dg.AttackerCount != 1 || dg.ByCategory["modsec"] != 1 {
		t.Fatalf("digest = %+v, want one modsec attacker block", dg)
	}
	if got, want := dg.Records[0].Reason, "rule escalation: repeated denies"; got != want {
		t.Fatalf("digest reason = %q, want %q without coverage annotation", got, want)
	}
}

func TestObserveBlocksCloudflareWarningDoesNotReplaceMissingReason(t *testing.T) {
	d := &Daemon{}
	d.blockDigest = blockdigest.New(blockdigest.Options{
		Watch: true, SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now:       func() time.Time { return time.Unix(0, 0) },
		CountryOf: func(string) string { return "RO" },
	})
	d.observeBlocks([]alert.Finding{{
		Check:     "auto_block",
		Severity:  alert.Critical,
		Message:   "AUTO-BLOCK: 203.0.113.57 blocked (expires in 24h)",
		Details:   "Reason:  (warning: IP is inside a Cloudflare allow range; ports 80/443 from it are still accepted)",
		Timestamp: time.Unix(0, 0),
	}})

	if dg := d.blockDigest.Drain(); dg.Total != 0 {
		t.Fatalf("digest = %+v, coverage annotation must not become a block reason", dg)
	}
}

func TestObserveBlocksNilCollectorIsNoop(t *testing.T) {
	d := &Daemon{} // blockDigest nil (feature disabled)
	d.observeBlocks([]alert.Finding{{Check: "auto_block", Severity: alert.Critical,
		Details: "Reason: x", Message: "AUTO-BLOCK: 1.2.3.4 blocked"}})
	// must not panic
}

func TestObserveBlocksSkipsDryRunSubnetNotices(t *testing.T) {
	d := &Daemon{}
	d.blockDigest = blockdigest.New(blockdigest.Options{
		Watch: true, SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now:       func() time.Time { return time.Unix(0, 0) },
		CountryOf: func(string) string { return "RO" },
	})
	d.observeBlocks([]alert.Finding{
		{
			Check: "auto_block", Severity: alert.Warning,
			Message: "AUTO-BLOCK-SUBNET [dry-run]: 203.0.113.0/24 would be blocked",
			Details: "Reason: mail auth brute force", Timestamp: time.Unix(0, 0),
		},
		{
			Check: "auto_block", Severity: alert.Warning,
			Message: "AUTO-NETBLOCK [dry-run]: 198.51.100.0/24 would be blocked",
			Details: "Reason: rule escalation", Timestamp: time.Unix(0, 0),
		},
	})

	if digest := d.blockDigest.Drain(); digest.Total != 0 {
		t.Fatalf("digest = %+v, dry-run notices must not be classified as live blocks", digest)
	}
}

func TestBlockDigestSinksChannelSelection(t *testing.T) {
	previousActive := config.Active()
	config.SetActive(nil)
	previousEmail, previousWebhook := blockDigestSendEmail, blockDigestSendWebhookJSON
	t.Cleanup(func() {
		config.SetActive(previousActive)
		blockDigestSendEmail, blockDigestSendWebhookJSON = previousEmail, previousWebhook
	})
	for _, channel := range []string{"", "email", "webhook"} {
		t.Run(channel, func(t *testing.T) {
			emails, webhooks := 0, 0
			blockDigestSendEmail = func(*config.Config, string, string) error { emails++; return nil }
			blockDigestSendWebhookJSON = func(*config.Config, any) error { webhooks++; return nil }
			cfg := &config.Config{}
			cfg.Alerts.Email.Enabled, cfg.Alerts.Webhook.Enabled = true, true
			cfg.Alerts.BlockDigest.Enabled, cfg.Alerts.BlockDigest.Live = true, true
			cfg.Alerts.BlockDigest.Channel = channel
			d := New(cfg, nil, nil, "")
			c := d.buildBlockDigest(cfg)
			c.Observe("192.0.2.1", "fixture block", time.Now())
			wantEmail, wantWebhook := 1, 1
			if channel == "email" {
				wantWebhook = 0
			}
			if channel == "webhook" {
				wantEmail = 0
			}
			if emails != wantEmail || webhooks != wantWebhook {
				t.Fatalf("live alert email=%d webhook=%d, want %d/%d", emails, webhooks, wantEmail, wantWebhook)
			}
		})
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

// The collector sends the daily summary on every daemon. With block_digest
// off it only stops watching blocks by country.
func TestBuildBlockDigestAlwaysBuilds(t *testing.T) {
	prevActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prevActive) })
	prevEmail := blockDigestSendEmail
	t.Cleanup(func() { blockDigestSendEmail = prevEmail })
	var subjects []string
	blockDigestSendEmail = func(_ *config.Config, subject, _ string) error {
		subjects = append(subjects, subject)
		return nil
	}

	cfg := &config.Config{Hostname: "host.example.com"}
	cfg.Alerts.BlockDigest.Enabled = false
	cfg.Alerts.Email.Enabled = true
	d := New(cfg, nil, nil, "")
	d.blockDigest = d.buildBlockDigest(cfg)
	if d.blockDigest == nil {
		t.Fatal("disabled block_digest built no collector; the daily summary needs one")
	}
	if _, ok := d.QueueStatuses()["block_digest.records"]; !ok {
		t.Fatal("collector queue rows missing with block_digest off")
	}
	d.observeBlocks([]alert.Finding{{Check: "auto_block", Severity: alert.Critical,
		Message: "AUTO-BLOCK: 192.0.2.61 blocked (expires in 24h)", Details: "Reason: fixture customer block", Timestamp: time.Now()}})
	if row := d.QueueStatuses()["block_digest.records"]; row.Depth != 0 {
		t.Fatalf("block_digest off still buffers watched blocks: %+v", row)
	}
	if !d.blockDigest.SendDue(time.Now().Add(25 * time.Hour)) {
		t.Fatal("daily summary not due a day later")
	}
	if len(subjects) != 1 || !strings.HasPrefix(subjects[0], "[CSM] host.example.com - daily summary ") {
		t.Fatalf("summary emails = %q", subjects)
	}
}

// block_digest.channel selects live alerts only (P3-R16): the summary follows
// the enabled alert channels, with or without block_digest.
func TestDailySummaryIgnoresLiveChannelSelection(t *testing.T) {
	previousActive := config.Active()
	config.SetActive(nil)
	previousEmail, previousWebhook := blockDigestSendEmail, blockDigestSendWebhookJSON
	t.Cleanup(func() {
		config.SetActive(previousActive)
		blockDigestSendEmail, blockDigestSendWebhookJSON = previousEmail, previousWebhook
	})
	cases := []struct {
		name                   string
		channel                string
		emailOn, webhookOn     bool
		wantEmail, wantWebhook int
	}{
		{"email channel, both on", "email", true, true, 1, 1},
		{"webhook channel, both on", "webhook", true, true, 1, 1},
		{"webhook channel, only email on", "webhook", true, false, 1, 0},
		{"email channel, both off", "email", false, false, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			emails, webhooks := 0, 0
			blockDigestSendEmail = func(*config.Config, string, string) error { emails++; return nil }
			blockDigestSendWebhookJSON = func(*config.Config, any) error { webhooks++; return nil }
			cfg := &config.Config{}
			cfg.Alerts.BlockDigest.Channel = tc.channel
			cfg.Alerts.Email.Enabled, cfg.Alerts.Webhook.Enabled = tc.emailOn, tc.webhookOn
			d := New(cfg, nil, nil, "")
			c := d.buildBlockDigest(cfg)
			c.SendDue(time.Now().Add(25 * time.Hour))
			if emails != tc.wantEmail || webhooks != tc.wantWebhook {
				t.Fatalf("daily summary delivered email=%d webhook=%d, want %d/%d", emails, webhooks, tc.wantEmail, tc.wantWebhook)
			}
			// A sink error is what logs a delivery failure and counts a loss.
			for name, row := range d.QueueStatuses() {
				if strings.HasPrefix(name, "block_digest.") && (row.DroppedTotal != 0 || row.Depth != 0 || row.InFlight != 0) {
					t.Fatalf("%s after the summary: %+v, want no loss or pending work", name, row)
				}
			}
		})
	}
}

func TestShutdownDrainSavesLateSummaryFindings(t *testing.T) {
	var saved []byte
	d := &Daemon{}
	d.blockDigest = blockdigest.New(blockdigest.Options{
		SaveSummary: func(b []byte) error { saved = append([]byte(nil), b...); return nil },
	})
	stop := make(chan struct{})
	close(stop)
	d.blockDigest.Run(stop, nil)
	// A producer already dispatching when stopCh closes can finish after
	// the summary loop has checkpointed its window.
	d.noteSummary(&config.Config{}, []alert.Finding{{Check: "challenge_route", Severity: alert.Warning}})
	d.flushPendingAlertsOnShutdown()
	var summary blockdigest.Summary
	if err := json.Unmarshal(saved, &summary); err != nil {
		t.Fatal(err)
	}
	if got := summary.Checks["challenge_route"]["WARNING"]; got != 1 {
		t.Fatalf("final shutdown checkpoint lost a late finding: %d", got)
	}
}

func TestSummaryLifetimeEnclosesAdmission(t *testing.T) {
	// Admission can publish a recovered response immediately on startup
	// and a final response while stopping. Its summary receiver must exist
	// for that entire lifetime, with its last checkpoint after the drain.
	source, err := os.ReadFile("daemon.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	at := func(call string) int {
		i := strings.Index(text, call)
		if i < 0 {
			t.Fatalf("missing lifecycle call %q", call)
		}
		return i
	}
	if at("d.blockDigest = d.buildBlockDigest(") > at("d.startAdmission()") || at("alert.SetSummaryHook(d.noteSummary)") > at("d.startAdmission()") {
		t.Fatal("admission can dispatch before the summary receiver exists")
	}
	if at("alert.SetSummaryHook(nil)") < at("d.stopAdmission()") || at("alert.SetSummaryHook(nil)") < at("d.flushPendingAlertsOnShutdown()") {
		t.Fatal("summary receiver stops before the final producer drain")
	}
}

func TestNoteSummaryMapsFindings(t *testing.T) {
	var got []blockdigest.WebhookPayload
	d := &Daemon{}
	d.blockDigest = blockdigest.New(blockdigest.Options{
		Interval: time.Hour, SendOn: "any", MinBlock: 1, Location: time.UTC,
		WebhookSink: func(p blockdigest.WebhookPayload) error { got = append(got, p); return nil },
	})
	cfg := &config.Config{}
	cfg.Alerts.Email.DisabledChecks = []string{" challenge_route ", "ftp_login"}
	d.noteSummary(cfg, []alert.Finding{
		{Check: "auto_block", Severity: alert.Critical, Message: "AUTO-BLOCK: 203.0.113.20 blocked (expires in 24h)",
			Details: "Reason: ModSecurity escalation: 5+ denies (warning: " + firewall.CloudflareCoverageWarning + ")"},
		{Check: "auto_block", Severity: alert.Critical, Message: "AUTO-PERMBLOCK: 203.0.113.20 promoted to permanent block (4 temp blocks)", SourceIP: "203.0.113.20"},
		{Check: "auto_block", Severity: alert.Critical, Message: "AUTO-NETBLOCK: 198.51.100.0/24 blocked (5 IPs from same subnet)"},
		{Check: "auto_block", Severity: alert.Warning, Message: "AUTO-BLOCK-SUBNET [dry-run]: 198.51.100.0/24 would be blocked", Details: "Reason: mail auth brute force"},
		{Check: "challenge_route", Severity: alert.Warning, Message: "CHALLENGE: 198.51.100.7 sent to PoW challenge (expires in 30m0s)"},
		{Check: "wp_login_bruteforce", Severity: alert.Critical, Message: "WordPress login brute force from 203.0.113.20", SourceIP: "203.0.113.20"},
		{Check: "ftp_login_realtime", Severity: alert.High, Message: "FTP login", SourceIP: "192.0.2.30"},
	})
	d.noteSummary(cfg, nil)
	if !d.blockDigest.SendDue(time.Now().Add(25*time.Hour)) || len(got) != 1 {
		t.Fatalf("summary webhooks = %d, want 1", len(got))
	}
	s := got[0].CSM.Summary
	if s == nil {
		t.Fatal("no csm.summary")
	}
	if c := s.Checks["auto_block"]; c["CRITICAL"] != 3 || c["WARNING"] != 1 {
		t.Fatalf("auto_block = %v, want CRITICAL=3 WARNING=1", c)
	}
	if s.Checks["challenge_route"]["WARNING"] != 1 || s.Checks["wp_login_bruteforce"]["CRITICAL"] != 1 {
		t.Fatalf("checks = %v", s.Checks)
	}
	if s.Checks["ftp_login"]["HIGH"] != 1 || s.Checks["ftp_login_realtime"] != nil {
		t.Fatalf("checks = %v, want the legacy name counted under its current name", s.Checks)
	}
	// Netblock and permanent-block notices carry no reason; their message
	// names the kind. The dry-run verdict is not an applied block.
	wantKinds := map[string]int{"modsec": 1, "permanent": 1, "netblock": 1}
	if s.Blocks != 3 || len(s.BlockKinds) != len(wantKinds) {
		t.Fatalf("blocks = %d %v, want %v without the coverage annotation", s.Blocks, s.BlockKinds, wantKinds)
	}
	for kind, n := range wantKinds {
		if s.BlockKinds[kind] != n {
			t.Fatalf("block kinds = %v, want %v", s.BlockKinds, wantKinds)
		}
	}
	if s.Muted != 2 {
		t.Fatalf("muted = %d, want 2 (challenge_route and ftp_login are in disabled_checks)", s.Muted)
	}
	want := map[string]int{"203.0.113.20": 3, "198.51.100.7": 1, "192.0.2.30": 1}
	if len(s.Sources) != len(want) {
		t.Fatalf("sources = %+v, want %v", s.Sources, want)
	}
	for _, src := range s.Sources {
		if want[src.IP] != src.Count {
			t.Fatalf("sources = %+v, want %v", s.Sources, want)
		}
	}
}

// A noteSummary panic must not reach dispatch.
func TestNoteSummaryNeverPanics(t *testing.T) {
	d := &Daemon{blockDigest: blockdigest.New(blockdigest.Options{Interval: time.Hour})}
	d.noteSummary(nil, []alert.Finding{{Check: "challenge_route", Severity: alert.Warning}})
	(&Daemon{}).noteSummary(&config.Config{}, []alert.Finding{{Check: "challenge_route"}})
}

// A phpanel webhook takes signed findings only. The daily summary must not
// create a webhook job there, so health counts no delivery for it; live
// block alerts keep reaching that URL as before.
func TestSummaryWebhookSkipsPhpanel(t *testing.T) {
	prevActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prevActive) })
	prevEmail, prevWebhook := blockDigestSendEmail, blockDigestSendWebhookJSON
	t.Cleanup(func() { blockDigestSendEmail, blockDigestSendWebhookJSON = prevEmail, prevWebhook })
	for _, hook := range []string{"phpanel", "generic"} {
		t.Run(hook, func(t *testing.T) {
			var events []string
			blockDigestSendWebhookJSON = func(_ *config.Config, payload any) error {
				events = append(events, payload.(blockdigest.WebhookPayload).CSM.Event)
				return nil
			}
			cfg := &config.Config{}
			cfg.Alerts.Email.Enabled = true
			cfg.Alerts.Webhook.Enabled = true
			cfg.Alerts.Webhook.Type = hook
			cfg.Alerts.BlockDigest.Enabled, cfg.Alerts.BlockDigest.Live = true, true
			d := New(cfg, nil, nil, "")
			c := d.buildBlockDigest(cfg)

			// Hold the summary email so the webhook row shows whether a
			// webhook job was created for the same summary.
			entered, release := make(chan struct{}), make(chan struct{})
			blockDigestSendEmail = func(*config.Config, string, string) error {
				close(entered)
				<-release
				return nil
			}
			done := make(chan struct{})
			go func() { defer close(done); c.SendDue(time.Now().Add(25 * time.Hour)) }()
			<-entered
			wantDepth := 1
			if hook == "phpanel" {
				wantDepth = 0
			}
			if row := d.QueueStatuses()["block_digest.webhook"]; row.Depth != wantDepth {
				close(release)
				<-done
				t.Fatalf("%s summary webhook jobs waiting = %d, want %d: %+v", hook, row.Depth, wantDepth, row)
			}
			close(release)
			<-done

			blockDigestSendEmail = func(*config.Config, string, string) error { return nil }
			c.Observe("192.0.2.1", "fixture block", time.Now())
			want := "daily_summary,block_live"
			if hook == "phpanel" {
				want = "block_live"
			}
			if got := strings.Join(events, ","); got != want {
				t.Fatalf("%s webhook sent %q, want %q", hook, got, want)
			}
			if row := d.QueueStatuses()["block_digest.webhook"]; row.DroppedTotal != 0 || row.Depth != 0 || row.InFlight != 0 {
				t.Fatalf("%s webhook row = %+v", hook, row)
			}
		})
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
		Watch:        true,
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
