//go:build linux

package firewall

import (
	"fmt"
	"os"
	"sort"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// LockedLocalPorts returns the ports the engine's current config locks,
// sorted.
func (e *Engine) LockedLocalPorts() []int {
	cfg := e.Config()
	if cfg == nil {
		return nil
	}
	locks, err := ParseLocalPortLocks(cfg.LocalPortLocks)
	if err != nil {
		return nil
	}
	ports := make([]int, 0, len(locks))
	for _, l := range locks {
		ports = append(ports, l.Port)
	}
	sort.Ints(ports)
	return ports
}

// addLocalPortLockRules accepts new loopback TCP connections to each locked
// port from root and the listed users, and resets everyone else's. Packets
// of established connections and traffic to other hosts do not match.
func (e *Engine) addLocalPortLockRules() {
	locks, err := ParseLocalPortLocks(e.cfg.LocalPortLocks)
	if err != nil {
		// Config load rejects this; never reached from a validated config.
		fmt.Fprintf(os.Stderr, "firewall: local_port_locks: %v\n", err)
		return
	}
	for _, l := range locks {
		for _, uid := range resolveLockUIDs(l.Port, l.Users) {
			exprs := append(localPortLockMatch(l.Port),
				&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uid)},
				&expr.Verdict{Kind: expr.VerdictAccept},
			)
			e.conn.AddRule(&nftables.Rule{Table: e.table, Chain: e.chainOut, Exprs: exprs})
		}
		e.conn.AddRule(&nftables.Rule{
			Table: e.table,
			Chain: e.chainOut,
			Exprs: append(localPortLockMatch(l.Port), &expr.Reject{Type: 1}), // NFT_REJECT_TCP_RST
		})
	}
}

func localPortLockMatch(port int) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("lo\x00")},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(portU16(port))},
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW),
			Xor:  binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
	}
}
