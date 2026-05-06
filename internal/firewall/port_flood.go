//go:build linux

package firewall

import (
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// buildPortFloodExprs returns the nftables expressions for one per-port
// flood-protection rule. The rule rate-limits new TCP/UDP connections to
// pf.Port *per source IPv4 address* by updating a dynamic meter set —
// each source IP gets its own token bucket sized at pf.Hits per pf.Seconds.
//
// Returning nil signals the caller to skip rule creation (zero rate, missing
// meter, or zero-port).
//
// IPv6 traffic is filtered out (NFPROTO_IPV4) so v6 source addresses don't
// pollute the v4-keyed meter set with garbage keys.
func buildPortFloodExprs(pf PortFloodRule, meter *nftables.Set) []expr.Any {
	if meter == nil || pf.Hits <= 0 || pf.Seconds <= 0 || pf.Port <= 0 {
		return nil
	}

	proto := byte(6) // TCP
	if pf.Proto == "udp" {
		proto = 17
	}

	// hits/seconds → packets per minute (multiply first to keep precision).
	ratePerMin := uint64(pf.Hits) * 60 / uint64(pf.Seconds)
	if ratePerMin < 1 {
		ratePerMin = 1
	}
	burst := uint32(ratePerMin / 4)
	if burst < 2 {
		burst = 2
	}

	return []expr.Any{
		// Restrict to IPv4 — v6 packets must not key the v4 meter.
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{2}}, // NFPROTO_IPV4
		// Match new connections only.
		&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW),
			Xor:  binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		// L4 protocol filter (TCP or UDP).
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		// Destination port.
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(pf.Port))},
		// Load source IPv4 address into reg1 — this is the meter key.
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		// Update meter entry for this source IP, evaluating its own token bucket.
		&expr.Dynset{
			SrcRegKey: 1,
			SetName:   meter.Name,
			SetID:     meter.ID,
			Operation: 1, // NFT_DYNSET_OP_UPDATE
			Exprs: []expr.Any{
				&expr.Limit{Type: expr.LimitTypePkts, Rate: ratePerMin, Unit: expr.LimitTimeMinute, Burst: burst, Over: true},
			},
		},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}
