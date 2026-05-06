//go:build linux

package firewall

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// TestBuildPortFloodExprs_IsPerSourceIP_NotGlobal asserts that a port_flood
// rule meters the rate per source IP (via Dynset on a v4 meter set), not
// globally. A purely global limit punishes every connecting client when one
// noisy source pegs the counter — see the cluster-wide SMTP outage that
// motivated this fix.
func TestBuildPortFloodExprs_IsPerSourceIP_NotGlobal(t *testing.T) {
	meter := &nftables.Set{Name: "meter_port_flood", ID: 7}
	pf := PortFloodRule{Port: 25, Proto: "tcp", Hits: 600, Seconds: 300}

	exprs := buildPortFloodExprs(pf, meter)

	// The rule must restrict to IPv4 (NFPROTO_IPV4 = 2) before loading saddr,
	// otherwise IPv6 packets would key the v4 meter with junk bytes.
	if !hasNFProtoIPv4Filter(exprs) {
		t.Error("rule must restrict to NFPROTO_IPV4 before loading saddr")
	}

	// The rule must load source IP from the network header (offset 12, len 4).
	if !hasSourceIPLoad(exprs) {
		t.Error("rule must load source IP (PayloadBaseNetworkHeader offset 12 len 4)")
	}

	// The rate limit must be wrapped in a Dynset that updates the meter set
	// per source IP — i.e. each IP gets its own token bucket.
	dyn := findDynset(exprs)
	if dyn == nil {
		t.Fatal("rule must contain expr.Dynset (per-source-IP meter)")
	}
	if dyn.SetName != meter.Name {
		t.Errorf("Dynset.SetName = %q, want %q", dyn.SetName, meter.Name)
	}
	if dyn.SetID != meter.ID {
		t.Errorf("Dynset.SetID = %d, want %d", dyn.SetID, meter.ID)
	}
	if dyn.Operation != 1 {
		t.Errorf("Dynset.Operation = %d, want 1 (NFT_DYNSET_OP_UPDATE)", dyn.Operation)
	}

	// And the inner expression must be the Limit (token bucket per entry).
	var foundLimit *expr.Limit
	for _, e := range dyn.Exprs {
		if l, ok := e.(*expr.Limit); ok {
			foundLimit = l
			break
		}
	}
	if foundLimit == nil {
		t.Fatal("Dynset must contain an inner expr.Limit (per-IP token bucket)")
	}

	// 600 hits / 300s = 120 packets/min.
	if foundLimit.Rate != 120 {
		t.Errorf("Limit.Rate = %d, want 120 (600 hits / 300s)", foundLimit.Rate)
	}
	if foundLimit.Unit != expr.LimitTimeMinute {
		t.Errorf("Limit.Unit = %v, want LimitTimeMinute", foundLimit.Unit)
	}
	if !foundLimit.Over {
		t.Error("Limit.Over must be true (drop when rate exceeded)")
	}

	// The rule must end in a Drop verdict.
	if !endsWithDrop(exprs) {
		t.Error("rule must end with VerdictDrop")
	}
}

// TestBuildPortFloodExprs_FiltersTargetPort verifies that the rule only fires
// for the configured port, not all TCP traffic.
func TestBuildPortFloodExprs_FiltersTargetPort(t *testing.T) {
	meter := &nftables.Set{Name: "meter_port_flood", ID: 1}

	for _, port := range []int{25, 465, 587} {
		pf := PortFloodRule{Port: port, Proto: "tcp", Hits: 600, Seconds: 300}
		exprs := buildPortFloodExprs(pf, meter)
		if !hasDestPortFilter(exprs, port) {
			t.Errorf("port %d: rule must filter on transport-header dport", port)
		}
	}
}

func TestBuildPortFloodExprs_NilMeterReturnsNil(t *testing.T) {
	pf := PortFloodRule{Port: 25, Proto: "tcp", Hits: 600, Seconds: 300}
	if got := buildPortFloodExprs(pf, nil); got != nil {
		t.Errorf("buildPortFloodExprs with nil meter must return nil, got %d exprs", len(got))
	}
}

func TestBuildPortFloodExprs_ZeroRateReturnsNil(t *testing.T) {
	meter := &nftables.Set{Name: "meter_port_flood", ID: 1}
	pf := PortFloodRule{Port: 25, Proto: "tcp", Hits: 0, Seconds: 300}
	if got := buildPortFloodExprs(pf, meter); got != nil {
		t.Errorf("buildPortFloodExprs with Hits=0 must return nil, got %d exprs", len(got))
	}
}

// TestDefaultPortFloodTolerantOfNormalMUABursts encodes the operational
// requirement: the default per-IP rate must be high enough that a single
// Thunderbird/iPhone client opening 10–15 parallel SMTP connections (typical
// when sending one email with attachments, or batch IMAP+SMTP sync) does not
// trip the limiter. Anything below ~60/min/IP would fail real users.
func TestDefaultPortFloodTolerantOfNormalMUABursts(t *testing.T) {
	cfg := DefaultConfig()
	const minTolerableRatePerMin = 60

	for _, pf := range cfg.PortFlood {
		if pf.Hits <= 0 || pf.Seconds <= 0 {
			t.Errorf("port %d default has invalid rate hits=%d seconds=%d", pf.Port, pf.Hits, pf.Seconds)
			continue
		}
		ratePerMin := pf.Hits * 60 / pf.Seconds
		if ratePerMin < minTolerableRatePerMin {
			t.Errorf("port %d default %d/min is too low for normal MUA bursts (need ≥ %d/min)",
				pf.Port, ratePerMin, minTolerableRatePerMin)
		}
	}
}

// helpers --------------------------------------------------------------------

func hasNFProtoIPv4Filter(exprs []expr.Any) bool {
	for i := 0; i < len(exprs)-1; i++ {
		m, ok := exprs[i].(*expr.Meta)
		if !ok || m.Key != expr.MetaKeyNFPROTO {
			continue
		}
		c, ok := exprs[i+1].(*expr.Cmp)
		if !ok || c.Op != expr.CmpOpEq {
			continue
		}
		if len(c.Data) == 1 && c.Data[0] == 2 { // NFPROTO_IPV4
			return true
		}
	}
	return false
}

func hasSourceIPLoad(exprs []expr.Any) bool {
	for _, e := range exprs {
		p, ok := e.(*expr.Payload)
		if !ok {
			continue
		}
		if p.Base == expr.PayloadBaseNetworkHeader && p.Offset == 12 && p.Len == 4 {
			return true
		}
	}
	return false
}

func hasDestPortFilter(exprs []expr.Any, port int) bool {
	for i := 0; i < len(exprs)-1; i++ {
		p, ok := exprs[i].(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseTransportHeader || p.Offset != 2 || p.Len != 2 {
			continue
		}
		c, ok := exprs[i+1].(*expr.Cmp)
		if !ok || c.Op != expr.CmpOpEq || len(c.Data) != 2 {
			continue
		}
		got := int(c.Data[0])<<8 | int(c.Data[1])
		if got == port {
			return true
		}
	}
	return false
}

func findDynset(exprs []expr.Any) *expr.Dynset {
	for _, e := range exprs {
		if d, ok := e.(*expr.Dynset); ok {
			return d
		}
	}
	return nil
}

func endsWithDrop(exprs []expr.Any) bool {
	if len(exprs) == 0 {
		return false
	}
	v, ok := exprs[len(exprs)-1].(*expr.Verdict)
	return ok && v.Kind == expr.VerdictDrop
}
