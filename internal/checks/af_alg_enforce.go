package checks

import (
	"errors"
	"fmt"
	"os"
)

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

// afAlgMarkerPath is the canonical location of the CSM-managed mitigation
// marker. Its presence is the signal that operator-driven enforcement is
// active for this host.
const afAlgMarkerPath = "/etc/modprobe.d/csm-copy-fail-mitigation.conf"

// canonicalAFAlgMarker is the byte-exact content the enforcer writes and
// re-asserts on drift. Hand-written variants (`blacklist algif_aead`, etc.)
// still satisfy the hardening audit, but the enforcer rewrites them to this
// canonical form so the file's content can be trivially validated.
const canonicalAFAlgMarker = `# CSM Copy Fail (CVE-2026-31431) mitigation — managed by CSM.
# Restored automatically by the af_alg_enforce critical-tier check.
# Remove this file (and run ` + "`csm harden --copy-fail`" + ` again) if you
# need to re-enable AF_ALG.
install algif_aead /bin/false
install af_alg /bin/false
`

// EnforceResult describes what enforceAFAlgBlocked observed and did, in a
// shape both the CLI subcommand and the periodic Check function can format
// for the operator without re-deriving the same conclusions.
//
// ModuleUnloaded reports the OBSERVED post-call state, not the syscall
// attempt: it is true only when /proc/modules no longer contains the
// targeted modules after `modprobe -r` ran. Use this field to distinguish
// "unload succeeded" from "unload attempted but module is in use".
type EnforceResult struct {
	Action         EnforceAction
	MarkerPresent  bool
	MarkerValid    bool
	ModulesLoaded  []string // names of currently-loaded targeted modules at start of call
	MarkerWritten  bool     // wrapper wrote/restored the marker file this call
	ModuleUnloaded bool     // post-call /proc/modules shows targeted modules gone
	Notes          []string // operator-readable lines (warnings, stuck-module names)
}

func validateMarkerContent(data []byte) bool {
	return string(data) == canonicalAFAlgMarker
}

// loadedTargetedModules returns the subset of {algif_aead, af_alg} currently
// present in /proc/modules. Used both before unload (to decide what to do)
// and after unload (to verify it actually took effect).
func loadedTargetedModules() []string {
	var loaded []string
	for _, mod := range loadModuleList() {
		if mod == "algif_aead" || mod == "af_alg" {
			loaded = append(loaded, mod)
		}
	}
	return loaded
}

// enforceAFAlgBlocked inspects the marker file and /proc/modules, calls the
// pure decideAFAlgEnforcement, and applies the resulting action via osFS
// and cmdExec. Errors from osFS.WriteFile or unexpected osFS.Stat failures
// are returned; modprobe outcomes are observed via a post-call /proc/modules
// re-read (RunAllowNonZero swallows the non-zero exit, so the only reliable
// signal that the unload actually took effect is the kernel's module table).
func enforceAFAlgBlocked() (EnforceResult, error) {
	res := EnforceResult{}

	// Marker presence + content check. ErrNotExist is the expected "advisory
	// mode" path; any other Stat failure (e.g. EACCES on a hardened
	// /etc/modprobe.d/) is surfaced as an error rather than silently
	// classifying the host as advisory mode.
	switch _, err := osFS.Stat(afAlgMarkerPath); {
	case err == nil:
		res.MarkerPresent = true
		if data, err := osFS.ReadFile(afAlgMarkerPath); err == nil {
			res.MarkerValid = validateMarkerContent(data)
		}
	case errors.Is(err, os.ErrNotExist):
		// Advisory mode — operator has not opted in.
	default:
		return res, fmt.Errorf("stat %s: %w", afAlgMarkerPath, err)
	}

	res.ModulesLoaded = loadedTargetedModules()

	res.Action = decideAFAlgEnforcement(res.MarkerPresent, res.MarkerValid, len(res.ModulesLoaded) > 0)

	switch res.Action {
	case EnforceActionRestoreMarker, EnforceActionRestoreAndUnload:
		if err := osFS.WriteFile(afAlgMarkerPath, []byte(canonicalAFAlgMarker), 0o644); err != nil {
			return res, err
		}
		res.MarkerWritten = true
	}

	switch res.Action {
	case EnforceActionUnloadModules, EnforceActionRestoreAndUnload:
		_, _ = cmdExec.RunAllowNonZero("modprobe", "-r", "algif_aead", "af_alg")
		// Re-read /proc/modules to see whether the unload actually took
		// effect. RunAllowNonZero swallows non-zero exits (modprobe returns
		// 1 when a module is in use), and the helper's underlying
		// .Output() captures stdout only — modprobe writes its "FATAL:
		// module in use" message to stderr — so the only reliable signal
		// is the post-call kernel state.
		stillLoaded := loadedTargetedModules()
		if len(stillLoaded) == 0 {
			res.ModuleUnloaded = true
		} else {
			res.Notes = append(res.Notes, fmt.Sprintf(
				"modprobe -r attempted but %v still loaded — module is in use; will retry next tick",
				stillLoaded,
			))
		}
	}

	return res, nil
}
