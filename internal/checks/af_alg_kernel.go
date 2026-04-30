package checks

import (
	"bytes"
	"compress/gzip"
	"os"
	"strings"
)

// copyFailCVE is the CVE identifier used to match KernelCare/kpatch entries.
const copyFailCVE = "CVE-2026-31431"

// configHasBuiltInAFAlgAEAD reports whether the supplied kernel config text
// declares CRYPTO_USER_API_AEAD as built into the kernel image (=y) rather
// than as a loadable module (=m). On =y kernels, the modprobe blacklist
// mitigation is ineffective because there is no module to block from
// loading — the code is always present.
//
// The function tolerates the "is not set" comment form that kconfig uses
// for explicitly-disabled options. An unset CRYPTO_USER_API_AEAD returns
// false (not built-in; modular or absent).
func configHasBuiltInAFAlgAEAD(configText string) bool {
	for _, line := range strings.Split(configText, "\n") {
		line = strings.TrimSpace(line)
		if line == "CONFIG_CRYPTO_USER_API_AEAD=y" {
			return true
		}
	}
	return false
}

// configHasModularAFAlgAEAD reports whether CRYPTO_USER_API_AEAD is set
// to =m (loadable module) in the supplied kernel config. Used by the
// "is this host actually exploitable?" policy decision: a kernel built
// without =y AND without =m has no AF_ALG aead interface at all, so
// Copy Fail is not reachable on it.
func configHasModularAFAlgAEAD(configText string) bool {
	for _, line := range strings.Split(configText, "\n") {
		line = strings.TrimSpace(line)
		if line == "CONFIG_CRYPTO_USER_API_AEAD=m" {
			return true
		}
	}
	return false
}

// kcareReportsCopyFailPatched reports whether the supplied `kcarectl
// --patch-info` output advertises a patch covering the Copy Fail CVE.
// The kcarectl format emits per-patch records like:
//
//	kpatch-name: rhel8/.../CVE-2026-NNNNN-foo.patch
//	kpatch-cve: CVE-2026-NNNNN
//	kpatch-cve-url: ...
//
// We match on a substring of the literal CVE id rather than the URL or
// filename so a future format change to either does not silently break
// detection.
func kcareReportsCopyFailPatched(out []byte) bool {
	return bytes.Contains(out, []byte(copyFailCVE))
}

// kernelHasBuiltInAFAlgAEAD is the impure wrapper: it reads the kernel
// config from /boot/config-$(uname -r), falling back to /proc/config.gz,
// and asks configHasBuiltInAFAlgAEAD whether the AEAD interface is
// statically linked.
//
// Returns (false, nil) when no config file is readable — the caller
// treats "config unknown" the same as "modular" so an inability to read
// the config never silently downgrades a real protection state.
func kernelHasBuiltInAFAlgAEAD() (bool, error) {
	cfg, _ := readKernelConfigText()
	if cfg == "" {
		return false, nil
	}
	return configHasBuiltInAFAlgAEAD(cfg), nil
}

// readKernelConfigText returns the running kernel's .config text from
// /boot/config-$(uname -r), falling back to /proc/config.gz (gunzipped).
// Returns ("", false) when neither is readable so the caller can decide
// whether to treat "unknown" as conservatively-vulnerable.
func readKernelConfigText() (string, bool) {
	if uname, err := readKernelRelease(); err == nil {
		if data, err := osFS.ReadFile("/boot/config-" + uname); err == nil {
			return string(data), true
		}
	}
	if data, err := osFS.ReadFile("/proc/config.gz"); err == nil {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return "", false
		}
		defer func() { _ = zr.Close() }()
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(zr); err != nil {
			return "", false
		}
		return buf.String(), true
	}
	return "", false
}

// readKernelRelease returns the running kernel release string (the same
// value `uname -r` would print). Used to find the matching config-* file
// under /boot.
func readKernelRelease() (string, error) {
	data, err := osFS.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// kcareHasCopyFailPatch runs `kcarectl --patch-info` and reports whether
// KernelCare has applied a livepatch covering Copy Fail. Returns false
// (with a nil error) when kcarectl is absent or fails — KernelCare is
// optional and its absence is not an error condition.
func kcareHasCopyFailPatch() bool {
	out, err := cmdExec.RunAllowNonZero("kcarectl", "--patch-info")
	if err != nil {
		return false
	}
	if len(out) == 0 {
		return false
	}
	return kcareReportsCopyFailPatched(out)
}

// AFAlgKernelState is the assembled view of how the running kernel
// exposes AF_ALG. Used by the hardening audit, by csm harden, and by
// the live-monitor coordinator to decide whether protection is needed.
type AFAlgKernelState struct {
	BuiltIn         bool // CONFIG_CRYPTO_USER_API_AEAD=y in the running kernel
	Modular         bool // CONFIG_CRYPTO_USER_API_AEAD=m (loadable module exists)
	ConfigReadable  bool // /boot/config-$(uname -r) or /proc/config.gz was parseable
	LivepatchActive bool // KernelCare/kpatch has applied a CVE-2026-31431 patch
}

// observeAFAlgKernelState assembles a kernel-state snapshot via the impure
// helpers above. The struct fields document precisely what we know vs
// what we couldn't determine — callers can apply policy without
// re-deriving the same probes.
func observeAFAlgKernelState() AFAlgKernelState {
	state := AFAlgKernelState{}
	if cfg, ok := readKernelConfigText(); ok {
		state.ConfigReadable = true
		state.BuiltIn = configHasBuiltInAFAlgAEAD(cfg)
		state.Modular = configHasModularAFAlgAEAD(cfg)
	}
	state.LivepatchActive = kcareHasCopyFailPatch()
	return state
}

// IsCopyFailExploitable reports whether this kernel is currently
// vulnerable to Copy Fail (CVE-2026-31431). Used by the daemon's
// live-monitor coordinator to skip starting the listener entirely on
// hosts that don't need protection — saving the inotify watch + tick
// loop for hosts that actually face the threat.
//
// Conservative defaults: when the kernel config is unreadable, treat
// the host as exploitable (better to over-monitor than miss). When a
// KernelCare livepatch is in place, treat as patched regardless of the
// underlying config — the syscall path itself is fixed.
func (s AFAlgKernelState) IsCopyFailExploitable() bool {
	if s.LivepatchActive {
		return false
	}
	if s.ConfigReadable && !s.BuiltIn && !s.Modular {
		// Kernel was definitively built without the AF_ALG aead interface.
		// Nothing to exploit, no listener needed.
		return false
	}
	// Either: confirmed-vulnerable (=y or =m without livepatch), or
	// unknown (config unreadable). Both go to "exploitable" so we err
	// on the side of monitoring.
	return true
}

// String renders the kernel state for inclusion in operator-visible
// messages. The format is stable and short enough to embed in a single
// AuditResult.Message line.
func (s AFAlgKernelState) String() string {
	switch {
	case s.LivepatchActive:
		return "kernel patched by KernelCare (livepatch active for " + copyFailCVE + ")"
	case s.BuiltIn:
		return "AF_ALG is built into the kernel (CONFIG_CRYPTO_USER_API_AEAD=y) and no livepatch is active"
	case s.Modular:
		return "AF_ALG aead is a loadable module on this kernel"
	case s.ConfigReadable:
		return "AF_ALG aead is not present in this kernel build"
	default:
		return "kernel config unreadable; treating as potentially vulnerable"
	}
}

// ObserveAFAlgKernelState is the exported alias for cmd/csm and the
// daemon. Production code inside this package uses the unexported form
// directly.
func ObserveAFAlgKernelState() AFAlgKernelState { return observeAFAlgKernelState() }

// EnsureFile is a sentinel return value: callers can use os.IsNotExist
// to test for the "kernel-config file absent" case explicitly.
var ErrKernelConfigUnreadable = os.ErrNotExist
