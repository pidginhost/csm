package daemon

import (
	"net"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func TestEvaluateConnectionEventFlagsBadASNForNonRoot(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.BadASNOutbound.Enabled = true
	cfg.Detection.BadASNOutbound.BlockedASNs = []uint{64500}
	checks.SetASNLookup(func(string) (uint, string) { return 64500, "Bulletproof LLC" })
	defer checks.SetASNLookup(nil)

	ev := ConnectionEvent{
		UID:     1001,
		Family:  2,
		DstPort: 443,
		DstIP:   net.ParseIP("203.0.113.9").To4(),
		Comm:    "miner",
	}

	got := evaluateConnectionEvent(cfg, platform.MTAIdents{}, ev, "alice")
	var found *struct{ ts bool }
	for i := range got {
		if got[i].Check == "bad_asn_outbound" {
			found = &struct{ ts bool }{ts: !got[i].Timestamp.IsZero()}
		}
	}
	if found == nil {
		t.Fatalf("expected bad_asn_outbound finding for non-root egress; got %+v", got)
	}
	if !found.ts {
		t.Fatal("bad_asn_outbound finding has zero Timestamp")
	}
}

func TestEvaluateConnectionEventSkipsRootBadASN(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.BadASNOutbound.Enabled = true
	cfg.Detection.BadASNOutbound.BlockedASNs = []uint{64500}
	called := false
	checks.SetASNLookup(func(string) (uint, string) {
		called = true
		return 64500, "Bulletproof LLC"
	})
	defer checks.SetASNLookup(nil)

	ev := ConnectionEvent{
		UID:     0,
		Family:  2,
		DstPort: 443,
		DstIP:   net.ParseIP("203.0.113.9").To4(),
		Comm:    "miner",
	}

	for _, f := range evaluateConnectionEvent(cfg, platform.MTAIdents{}, ev, "root") {
		if f.Check == "bad_asn_outbound" {
			t.Fatalf("BPF root event must not flag bad_asn_outbound; got %+v", f)
		}
	}
	if called {
		t.Fatal("BPF root event must not perform ASN lookup")
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
		DstPort: 443,
		DstIP:   net.ParseIP("203.0.113.9").To4(),
		Comm:    "curl",
	}

	for _, f := range evaluateConnectionEvent(cfg, platform.MTAIdents{}, ev, "alice") {
		if f.Check == "bad_asn_outbound" {
			t.Fatalf("good ASN must not flag bad_asn_outbound; got %+v", f)
		}
	}
}
