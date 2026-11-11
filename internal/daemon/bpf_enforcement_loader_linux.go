//go:build linux && bpf

package daemon

import (
	"errors"

	"github.com/cilium/ebpf"

	"github.com/pidginhost/csm/internal/daemon/connection_bpfprog"
)

// installBPFEnforcementPolicy writes the policy + protected_ports maps
// from the userspace-derived policy. Runs once at startup; SIGHUP can
// re-call it to apply hot-reloaded policy changes.
func installBPFEnforcementPolicy(objs *connection_bpfprog.ConnectionObjects, pol BPFEnforcementPolicy) error {
	zero := uint32(0)
	payload := connection_bpfprog.ConnectionPolicyState{
		Enforce: pol.Enforce,
		DryRun:  pol.DryRun,
		// #nosec G115 -- bounded by protected_ports BPF map max_entries=16
		ProtectedPorts: uint32(len(pol.Ports)),
	}
	if err := objs.Policy.Update(zero, payload, ebpf.UpdateAny); err != nil {
		return err
	}
	for _, port := range pol.Ports {
		if err := objs.ProtectedPorts.Update(port, uint8(1), ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

// installSafeUIDs syncs the safe_uids BPF map to uids. Called periodically
// (T7 refresher) and at startup (T10).
func installSafeUIDs(m *ebpf.Map, uids map[uint32]bool) error {
	var installed []uint32
	var uid uint32
	var present uint8
	it := m.Iterate()
	for it.Next(&uid, &present) {
		installed = append(installed, uid)
	}
	if err := it.Err(); err != nil {
		return err
	}
	// Delete first so a full map still has room for the new UIDs.
	for _, uid := range staleSafeUIDs(installed, uids) {
		if err := m.Delete(uid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	for uid := range uids {
		if err := m.Update(uid, uint8(1), ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}
