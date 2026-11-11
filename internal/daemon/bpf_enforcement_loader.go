package daemon

// PolicyMapPayload is the wire-shape of struct policy_state in the BPF
// program. Mirrors the C layout exactly: three uint32 fields, no
// alignment surprises (all fields are 4 bytes).
type PolicyMapPayload struct {
	Enforce        uint32
	DryRun         uint32
	ProtectedPorts uint32
}

// policyMapPayload converts the userspace policy into the wire shape
// the BPF program reads. Pure function; tests drive it without loading
// any actual BPF program.
func policyMapPayload(pol BPFEnforcementPolicy) PolicyMapPayload {
	return PolicyMapPayload{
		Enforce: pol.Enforce,
		DryRun:  pol.DryRun,
		// #nosec G115 -- bounded by protected_ports BPF map max_entries=16
		ProtectedPorts: uint32(len(pol.Ports)),
	}
}

// staleSafeUIDs returns the installed hosted UIDs (>= 1000) that next no
// longer exempts, so a deleted account's UID cannot stay exempt for whoever
// gets it next. System UIDs stay: hosted accounts never receive them, and
// keeping them means a bad passwd read cannot deny the host's mail daemons.
func staleSafeUIDs(installed []uint32, next map[uint32]bool) []uint32 {
	var stale []uint32
	for _, uid := range installed {
		if uid >= 1000 && !next[uid] {
			stale = append(stale, uid)
		}
	}
	return stale
}
