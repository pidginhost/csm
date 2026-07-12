//go:build linux

package firewall

import (
	"fmt"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

type portFloodIPFamily struct {
	name         string
	nfproto      byte
	sourceOffset uint32
	sourceLen    uint32
}

var (
	portFloodIPv4 = portFloodIPFamily{name: "v4", nfproto: 2, sourceOffset: 12, sourceLen: 4}
	portFloodIPv6 = portFloodIPFamily{name: "v6", nfproto: 10, sourceOffset: 8, sourceLen: 16}
)

// buildPortFloodExprs returns the nftables expressions for one per-port
// flood-protection rule. The rule rate-limits new TCP/UDP connections to
// pf.Port per source address by updating a dynamic meter set. The caller
// supplies a family-specific meter, so IPv4 and IPv6 do not share buckets.
//
// Returning nil signals the caller to skip rule creation (zero rate, missing
// meter, or zero-port).
func buildPortFloodExprs(pf PortFloodRule, meter *nftables.Set, family portFloodIPFamily) []expr.Any {
	if meter == nil || pf.Hits <= 0 || pf.Seconds <= 0 || pf.Port <= 0 {
		return nil
	}

	proto := byte(6) // TCP
	if pf.Proto == "udp" {
		proto = 17
	}

	// hits/seconds -> packets per minute (multiply first to keep precision).
	ratePerMin := uint64(pf.Hits) * 60 / uint64(pf.Seconds)
	if ratePerMin < 1 {
		ratePerMin = 1
	}
	burst := uint32(ratePerMin / 4)
	if burst < 2 {
		burst = 2
	}

	return []expr.Any{
		// Restrict to the family that matches the meter key type.
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family.nfproto}},
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
		// Load source address into reg1; this is the meter key.
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: family.sourceOffset, Len: family.sourceLen},
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

func (e *Engine) portFloodRuleExprs(pf PortFloodRule, meter *nftables.Set, family portFloodIPFamily) []expr.Any {
	exprs := buildPortFloodExprs(pf, meter, family)
	if exprs == nil || !isMailTCP(pf) {
		return exprs
	}

	var exempt []expr.Any
	switch {
	case family == portFloodIPv4 && e.setDOSExempt != nil:
		exempt = e.dosExemptV4Lookup(1)
	case family == portFloodIPv6 && e.setDOSExempt6 != nil:
		exempt = e.dosExemptV6Lookup(1)
	default:
		return exprs
	}

	guarded := make([]expr.Any, 0, len(exprs)+len(exempt))
	guarded = append(guarded, exprs[:2]...)
	guarded = append(guarded, exempt...)
	return append(guarded, exprs[2:]...)
}

func portFloodMeterName(pf PortFloodRule, family portFloodIPFamily) string {
	return fmt.Sprintf("meter_pf_%s_%d_%s", portFloodProto(pf), pf.Port, family.name)
}

func portFloodProto(pf PortFloodRule) string {
	if pf.Proto == "udp" {
		return "udp"
	}
	return "tcp"
}

// isMailTCP reports whether pf is a TCP rule for a standard mail relay or
// submission port (25, 465, 587). Only these ports receive the DoS-exempt
// inverted-lookup guard; all other TCP ports and UDP rules are left unchanged.
func isMailTCP(pf PortFloodRule) bool {
	if !strings.EqualFold(pf.Proto, "tcp") {
		return false
	}
	switch pf.Port {
	case 25, 465, 587:
		return true
	default:
		return false
	}
}
