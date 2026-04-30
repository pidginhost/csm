package checks

import (
	"bufio"
	"strings"
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
type EnforceResult struct {
	Action         EnforceAction
	MarkerPresent  bool
	MarkerValid    bool
	ModulesLoaded  []string // names of currently-loaded targeted modules, if any
	MarkerWritten  bool     // wrapper wrote/restored the marker file this call
	ModuleUnloaded bool     // wrapper invoked modprobe -r this call
	Notes          []string // operator-readable lines (warnings, modprobe stderr)
}

func validateMarkerContent(data []byte) bool {
	return string(data) == canonicalAFAlgMarker
}

// enforceAFAlgBlocked inspects the marker file and /proc/modules, calls the
// pure decideAFAlgEnforcement, and applies the resulting action via osFS
// and cmdExec. Errors from osFS.WriteFile are returned; modprobe failures
// are downgraded to Notes because RunAllowNonZero already swallows the
// non-zero exit (the operator can re-check on the next tick).
func enforceAFAlgBlocked() (EnforceResult, error) {
	res := EnforceResult{}

	// Marker presence + content check.
	if _, err := osFS.Stat(afAlgMarkerPath); err == nil {
		res.MarkerPresent = true
		if data, err := osFS.ReadFile(afAlgMarkerPath); err == nil {
			res.MarkerValid = validateMarkerContent(data)
		}
	}

	// Module load check.
	for _, mod := range loadModuleList() {
		if mod == "algif_aead" || mod == "af_alg" {
			res.ModulesLoaded = append(res.ModulesLoaded, mod)
		}
	}
	loaded := len(res.ModulesLoaded) > 0

	res.Action = decideAFAlgEnforcement(res.MarkerPresent, res.MarkerValid, loaded)

	switch res.Action {
	case EnforceActionRestoreMarker, EnforceActionRestoreAndUnload:
		if err := osFS.WriteFile(afAlgMarkerPath, []byte(canonicalAFAlgMarker), 0o644); err != nil {
			return res, err
		}
		res.MarkerWritten = true
	}

	switch res.Action {
	case EnforceActionUnloadModules, EnforceActionRestoreAndUnload:
		out, _ := cmdExec.RunAllowNonZero("modprobe", "-r", "algif_aead", "af_alg")
		res.ModuleUnloaded = true
		// Surface modprobe's stderr on failure so the operator sees the
		// reason (e.g., "Module algif_aead is in use"). RunAllowNonZero
		// already absorbed the non-zero exit; we report verbatim.
		if msg := strings.TrimSpace(string(out)); msg != "" {
			scanner := bufio.NewScanner(strings.NewReader(msg))
			for scanner.Scan() {
				res.Notes = append(res.Notes, scanner.Text())
			}
		}
	}

	return res, nil
}
