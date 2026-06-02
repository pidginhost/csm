package daemon

import (
	"net"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func TestEvaluateConnectionEventFlagsBadASNIncludingRoot(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.BadASNOutbound.Enabled = true
	cfg.Detection.BadASNOutbound.BlockedASNs = []uint{64500}
	checks.SetASNLookup(func(string) (uint, string) { return 64500, "Bulletproof LLC" })
	defer checks.SetASNLookup(nil)

	// UID 0: the polling user_outbound detector skips root, but bad-ASN egress
	// from a post-exploit root process is exactly what the live path must catch.
	ev := ConnectionEvent{
		UID:     0,
		Family:  2,
		DstPort: 4444,
		DstIP:   net.ParseIP("203.0.113.9").To4(),
		Comm:    "miner",
	}

	got := evaluateConnectionEvent(cfg, platform.MTAIdents{}, ev, "root")
	var found *struct{ ts bool }
	for i := range got {
		if got[i].Check == "bad_asn_outbound" {
			found = &struct{ ts bool }{ts: !got[i].Timestamp.IsZero()}
		}
	}
	if found == nil {
		t.Fatalf("expected bad_asn_outbound finding for root egress; got %+v", got)
	}
	if !found.ts {
		t.Fatal("bad_asn_outbound finding has zero Timestamp")
	}
}

func TestEvaluateConnectionEventGoodASNNotFlagged(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.BadASNOutbound.Enabled = true
	cfg.Detection.BadASNOutbound.BlockedASNs = []uint{64500}
	checks.SetASNLookup(func(string) (uint, string) { return 13335, "Cloudflare" })
	defer checks.SetASNLookup(nil)

	ev := ConnectionEvent{
		UID:     1001,
		Family:  2,
		DstPort: 4444,
		DstIP:   net.ParseIP("203.0.113.9").To4(),
		Comm:    "curl",
	}

	for _, f := range evaluateConnectionEvent(cfg, platform.MTAIdents{}, ev, "alice") {
		if f.Check == "bad_asn_outbound" {
			t.Fatalf("good ASN must not flag bad_asn_outbound; got %+v", f)
		}
	}
}
