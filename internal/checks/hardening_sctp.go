package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/systemdrun"
)

// kmod messages are not translated.
var sctpModuleMissing = regexp.MustCompile(`(?m)^modprobe: FATAL: Module sctp not found in directory /`)

const sctpBlockFix = "Set the effective modprobe install directive to 'install sctp /bin/false' if this host does not need SCTP."

func auditSCTP() store.AuditResult {
	r := store.AuditResult{Category: "os", Name: "os_sctp_blocked", Title: "SCTP Kernel Module Blocked", Status: "warn"}
	cfg, _ := readKernelConfigText()
	config := sctpKernelConfig(cfg)
	if config == "y" {
		r.Status, r.Message = "fail", "SCTP is built into the running kernel."
		r.Fix = "Use a kernel with SCTP disabled, or built as a module and blocked."
		return r
	}

	// Once the lock is set, modules cannot be loaded or unloaded until reboot.
	// Sample it before the module list so a concurrent load cannot be missed.
	disabled, lockErr := osFS.ReadFile("/proc/sys/kernel/modules_disabled")
	locked := lockErr == nil && strings.TrimSpace(string(disabled)) == "1"
	modules, err := osFS.ReadFile("/proc/modules")
	for line := range strings.SplitSeq(string(modules), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == "sctp" {
			r.Status, r.Message = "fail", "SCTP is loaded in the running kernel."
			if locked {
				r.Fix = sctpBlockFix + " Schedule a reboot to unload SCTP."
			} else {
				r.Fix = sctpBlockFix + " Stop SCTP consumers before running modprobe -r sctp."
			}
			return r
		}
	}
	switch {
	case config == "n":
		r.Status, r.Message = "pass", "Kernel has no SCTP support."
	case err != nil:
		r.Message = "Cannot read /proc/modules to determine whether SCTP is loaded."
	case config != "m":
		r.Message = "Cannot determine CONFIG_IP_SCTP for the running kernel."
	case locked:
		r.Status, r.Message = "pass", "SCTP is unloaded and kernel module loading is disabled."
	default:
		return auditSCTPModulePolicy(r)
	}
	return r
}

func sctpKernelConfig(config string) string {
	for line := range strings.SplitSeq(config, "\n") {
		switch strings.TrimSpace(line) {
		case "CONFIG_IP_SCTP=y":
			return "y"
		case "CONFIG_IP_SCTP=m":
			return "m"
		case "CONFIG_IP_SCTP=n", "# CONFIG_IP_SCTP is not set", "# CONFIG_INET is not set", "# CONFIG_NET is not set":
			return "n"
		}
	}
	return ""
}

func auditSCTPModulePolicy(r store.AuditResult) store.AuditResult {
	if err := checkModprobePolicyReadable(); err != nil {
		r.Message = err.Error()
		return r
	}

	// Ask kmod for the named module: an alias blacklist alone still permits
	// dependency loads. --show-depends never inserts modules or runs commands.
	plan, err := querySCTPModprobe("--show-depends")
	if err != nil {
		// EL8 builds SCTP as a module but ships it in kernel-modules-extra.
		// The kernel's on-demand load fails the same lookup, so a missing
		// module cannot load.
		if sctpModuleMissing.Match(plan) {
			r.Status, r.Message = "pass", "SCTP module is not installed for the running kernel."
			return r
		}
		r.Message = "Cannot determine the SCTP installation plan with modprobe."
		return r
	}
	switch sctpInstallPlan(string(plan)) {
	case "insert":
		r.Status, r.Message = "fail", "SCTP can load as a dependency. The modprobe plan includes an SCTP insertion."
		r.Fix = sctpBlockFix
	case "block":
		// A local alias can redirect even a lookup of the literal name.
		names, err := querySCTPModprobe("--resolve-alias")
		if err != nil || strings.TrimSpace(string(names)) != "sctp" {
			r.Message = "Cannot resolve the blocked install command to the SCTP module."
			return r
		}
		r.Status, r.Message = "pass", "SCTP is blocked and unloaded."
	default:
		r.Message = "CSM cannot confirm an SCTP block from the modprobe installation plan."
	}
	return r
}

// ProtectKernelModules hides the module indexes from csm.service. The
// transient query needs to read host policy even when its mode is restrictive.
func querySCTPModprobe(option string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), auditCmdTimeout)
	defer cancel()
	return systemdrun.Run(ctx, cmdExec.LookPath, cmdExec.RunContext, systemdrun.Options{
		Pipe: true, RuntimeMax: auditCmdTimeout,
		Properties: []string{"CapabilityBoundingSet=CAP_DAC_READ_SEARCH", "NoNewPrivileges=yes", "ProtectSystem=strict"},
	}, "modprobe", option, "sctp")
}

// kmod can silently skip a file it cannot open. Check the visible files
// once per basename in modprobe.d directory precedence order.
func checkModprobePolicyReadable() error {
	seen := make(map[string]bool)
	for _, dir := range []string{"/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"} {
		entries, err := osFS.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("cannot read modprobe configuration directory %s: %w", dir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			ext := filepath.Ext(name)
			if entry.IsDir() || strings.HasPrefix(name, ".") || seen[name] || (ext != ".conf" && ext != ".alias") {
				continue
			}
			seen[name] = true
			path := filepath.Join(dir, name)
			if _, err := osFS.ReadFile(path); err != nil {
				return fmt.Errorf("cannot read modprobe configuration %s: %w", path, err)
			}
		}
	}
	return nil
}

func sctpInstallPlan(plan string) string {
	blocked := false
	for line := range strings.SplitSeq(strings.TrimSpace(plan), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return ""
		}
		switch fields[0] {
		case "insmod":
			name, _, ok := strings.Cut(filepath.Base(fields[1]), ".ko")
			if !ok || !filepath.IsAbs(fields[1]) {
				return ""
			}
			if name == "sctp" {
				return "insert"
			}
		case "builtin":
			if fields[1] == "sctp" {
				return ""
			}
		case "install":
			if len(fields) == 4 && (fields[1] == "/sbin/modprobe" || fields[1] == "/usr/sbin/modprobe" || fields[1] == "modprobe") &&
				(fields[2] == "--ignore-install" || fields[2] == "-i") && fields[3] == "sctp" {
				return "insert"
			}
			if len(fields) != 2 || blocked {
				return ""
			}
			switch fields[1] {
			case "/bin/false", "/usr/bin/false", "/bin/true", "/usr/bin/true":
				blocked = true
			default:
				return ""
			}
		default:
			return ""
		}
	}
	if blocked {
		return "block"
	}
	return ""
}
