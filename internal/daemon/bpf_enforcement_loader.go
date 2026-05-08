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
		Enforce:        pol.Enforce,
		DryRun:         pol.DryRun,
		ProtectedPorts: uint32(len(pol.Ports)),
	}
}
