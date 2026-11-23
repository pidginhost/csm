//go:build linux

package firewall

import (
	"fmt"
	"os"
	"slices"
	"sort"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// LockedLocalPorts reports installed locks only while the live rules still
// match the installation. A rollback or external edit invalidates that proof.
func (e *Engine) LockedLocalPorts() []int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.lockedLocalPorts) == 0 || e.appliedRuleset == "" {
		return nil
	}
	current, err := e.readRulesetLocked()
	if err != nil || current != e.appliedRuleset {
		return nil
	}
	return slices.Clone(e.lockedLocalPorts)
}

// LockedLocalPortUIDs reports the identities admitted by the acknowledged
// transaction, not by a config edit or a later account database change.
func (e *Engine) LockedLocalPortUIDs() map[int][]uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.lockedLocalUIDs) == 0 || e.appliedRuleset == "" {
		return nil
	}
	current, err := e.readRulesetLocked()
	if err != nil || current != e.appliedRuleset {
		return nil
	}
	out := make(map[int][]uint32, len(e.lockedLocalUIDs))
	for port, uids := range e.lockedLocalUIDs {
		out[port] = slices.Clone(uids)
	}
	return out
}

func configuredLockPorts(cfg *FirewallConfig) []int {
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
	e.pendingLocalUIDs = make(map[int][]uint32)
	locks, err := ParseLocalPortLocks(e.cfg.LocalPortLocks)
	if err != nil {
		// Config load rejects this; never reached from a validated config.
		fmt.Fprintf(os.Stderr, "firewall: local_port_locks: %v\n", err)
		return
	}
	for _, l := range locks {
		uids := resolveLockUIDs(l.Port, l.Users)
		e.pendingLocalUIDs[l.Port] = uids
		for _, uid := range uids {
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
		// SYN set and ACK clear opens a connection. The TCP flags, unlike
		// conntrack state, still match where loopback traffic is untracked.
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x12}, Xor: []byte{0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}},
	}
}
