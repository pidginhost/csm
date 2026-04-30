package checks

// EnforceAction is the discrete outcome of the pure enforcement decision.
// Each value corresponds to one operational step the impure wrapper takes.
type EnforceAction int

const (
	EnforceActionNoop EnforceAction = iota
	EnforceActionRestoreMarker
	EnforceActionUnloadModules
	EnforceActionRestoreAndUnload
)

// decideAFAlgEnforcement is the pure, deterministic core of the enforcement
// check. Given the observed state of the marker file and the kernel module
// table, it returns exactly one action.
//
// Inputs:
//   - markerPresent: /etc/modprobe.d/csm-copy-fail-mitigation.conf exists.
//   - markerContentValid: that file's contents match the canonical CSM-managed
//     content (so a hand-edited version still triggers a rewrite).
//   - loaded: algif_aead OR af_alg is currently in /proc/modules.
//
// The "marker absent + modules loaded" combination intentionally returns
// Noop. The operator has not opted in to enforcement (no marker), so we will
// not unilaterally unload kernel modules they may legitimately be using —
// the existing hardening audit and auditd tripwire still surface the gap.
func decideAFAlgEnforcement(markerPresent, markerContentValid, loaded bool) EnforceAction {
	if !markerPresent {
		return EnforceActionNoop
	}
	switch {
	case markerContentValid && !loaded:
		return EnforceActionNoop
	case markerContentValid && loaded:
		return EnforceActionUnloadModules
	case !markerContentValid && !loaded:
		return EnforceActionRestoreMarker
	default: // !markerContentValid && loaded
		return EnforceActionRestoreAndUnload
	}
}
