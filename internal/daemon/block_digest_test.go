package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
	"github.com/pidginhost/csm/internal/config"
)

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
	// default channel: follow whatever alerts has enabled
	e, w := d.blockDigestSinks(mk("", true, false))
	if e == nil || w != nil {
		t.Error("default channel with email enabled should give email sink only")
	}
	// explicit webhook overrides
	e, w = d.blockDigestSinks(mk("webhook", true, false))
	if e != nil || w == nil {
		t.Error("explicit webhook should give webhook sink only")
	}
	// default channel, both enabled -> both sinks
	e, w = d.blockDigestSinks(mk("", true, true))
	if e == nil || w == nil {
		t.Error("default channel with both enabled should give both sinks")
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
