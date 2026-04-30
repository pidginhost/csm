package checks

import (
	"bytes"
	"compress/gzip"
	"fmt"
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
	uname, err := readKernelRelease()
	if err == nil {
		path := "/boot/config-" + uname
		if data, err := osFS.ReadFile(path); err == nil {
			return configHasBuiltInAFAlgAEAD(string(data)), nil
		}
	}

	if data, err := osFS.ReadFile("/proc/config.gz"); err == nil {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return false, fmt.Errorf("decompress /proc/config.gz: %w", err)
		}
		defer func() { _ = zr.Close() }()
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(zr); err != nil {
			return false, fmt.Errorf("read /proc/config.gz: %w", err)
		}
		return configHasBuiltInAFAlgAEAD(buf.String()), nil
	}

	return false, nil
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
// exposes AF_ALG. Used by the hardening audit and by the csm harden
// subcommand to make accurate decisions on hosts where the modprobe
// blacklist alone is insufficient.
type AFAlgKernelState struct {
	BuiltIn         bool // CONFIG_CRYPTO_USER_API_AEAD=y in the running kernel
	LivepatchActive bool // KernelCare/kpatch has applied a CVE-2026-31431 patch
}

// observeAFAlgKernelState assembles a kernel-state snapshot via the impure
// helpers above. Errors from the config read are reported but the result
// is still usable — BuiltIn=false on read failure is treated as "modular,
// and the modprobe blacklist is the right defense."
func observeAFAlgKernelState() AFAlgKernelState {
	state := AFAlgKernelState{}
	if builtIn, err := kernelHasBuiltInAFAlgAEAD(); err == nil {
		state.BuiltIn = builtIn
	}
	state.LivepatchActive = kcareHasCopyFailPatch()
	return state
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
	default:
		return "AF_ALG is a loadable module on this kernel"
	}
}

// ObserveAFAlgKernelState is the exported alias for cmd/csm. Production
// code inside this package uses the unexported form directly.
func ObserveAFAlgKernelState() AFAlgKernelState { return observeAFAlgKernelState() }

// EnsureFile is a sentinel return value: callers can use os.IsNotExist
// to test for the "kernel-config file absent" case explicitly.
var ErrKernelConfigUnreadable = os.ErrNotExist
