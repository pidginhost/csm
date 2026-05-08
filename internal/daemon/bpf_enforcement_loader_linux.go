//go:build linux && bpf

package daemon

import (
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

// installSafeUIDs repopulates the safe_uids BPF map. Called periodically
// (T7 refresher) and at startup (T10).
func installSafeUIDs(objs *connection_bpfprog.ConnectionObjects, uids map[uint32]bool) error {
	for uid := range uids {
		if err := objs.SafeUids.Update(uid, uint8(1), ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}
