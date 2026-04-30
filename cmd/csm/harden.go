package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/pidginhost/csm/internal/checks"
)

func runHarden() {
	if len(os.Args) < 3 {
		fmt.Fprint(os.Stderr, hardenUsageString())
		os.Exit(1)
	}

	switch os.Args[2] {
	case "--copy-fail", "copy-fail":
		runHardenCopyFail()
	case "--copy-fail-seccomp", "copy-fail-seccomp":
		runHardenCopyFailSeccomp()
	default:
		fmt.Fprintf(os.Stderr, "Unknown harden subcommand: %s\n", os.Args[2])
		fmt.Fprint(os.Stderr, hardenUsageString())
		os.Exit(1)
	}
}

func runHardenCopyFailSeccomp() {
	// `--remove` rolls back: deletes the drop-ins CSM wrote and runs
	// daemon-reload + per-unit reload-or-restart. Idempotent.
	remove := false
	for _, a := range os.Args[3:] {
		if a == "--remove" || a == "remove" {
			remove = true
		}
	}

	if remove {
		removed, err := checks.RemoveAFAlgSeccompDropIns()
		if err != nil {
			fmt.Fprintf(os.Stderr, "csm: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("csm harden --copy-fail-seccomp --remove")
		fmt.Println("---------------------------------------")
		if len(removed) == 0 {
			fmt.Println("No CSM-managed seccomp drop-ins were present.")
			return
		}
		fmt.Printf("Removed drop-ins from %d units: %s\n", len(removed), strings.Join(removed, ", "))
		fmt.Println("AF_ALG access is no longer restricted by CSM. Confirm KernelCare or another mitigation is in place.")
		return
	}

	written, err := checks.ApplyAFAlgSeccompDropIns()
	if err != nil {
		fmt.Fprintf(os.Stderr, "csm: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("csm harden --copy-fail-seccomp")
	fmt.Println("------------------------------")
	if len(written) == 0 {
		fmt.Println("All candidate units already have the seccomp drop-in. Nothing changed.")
		summary := checks.SummarizeAFAlgSeccompCoverage()
		fmt.Printf("Coverage: %d covered, %d uncovered, %d not installed\n",
			len(summary.Covered), len(summary.Uncovered), len(summary.NotInstalled))
		return
	}

	fmt.Printf("Wrote drop-in to %d units and reloaded them:\n", len(written))
	for _, u := range written {
		fmt.Printf("  - %s\n", u)
	}
	fmt.Println()
	fmt.Println("Each unit now refuses socket(AF_ALG, ...) for itself and every")
	fmt.Println("process it spawns. Copy Fail (CVE-2026-31431) is unreachable")
	fmt.Println("through these services.")
	fmt.Println()
	fmt.Println("Roll back with: csm harden --copy-fail-seccomp --remove")
}

func runHardenCopyFail() {
	// Inspect the running kernel before doing anything operator-visible.
	// On kernels with CONFIG_CRYPTO_USER_API_AEAD=y (built-in), the modprobe
	// blacklist this command writes is ineffective — refusing here is
	// strictly better than silently writing a marker that misrepresents
	// the host's protection state.
	kstate := checks.ObserveAFAlgKernelState()
	if kstate.LivepatchActive {
		fmt.Println("csm harden --copy-fail")
		fmt.Println("--------------------------")
		fmt.Println("This kernel is already protected: KernelCare has applied a CVE-2026-31431 livepatch.")
		fmt.Println("No modprobe blacklist is needed. Nothing was changed.")
		return
	}
	if kstate.BuiltIn {
		fmt.Fprintln(os.Stderr, "csm harden --copy-fail: REFUSED")
		fmt.Fprintln(os.Stderr, "--------------------------------")
		fmt.Fprintln(os.Stderr, "This kernel has AF_ALG aead built into the kernel image")
		fmt.Fprintln(os.Stderr, "(CONFIG_CRYPTO_USER_API_AEAD=y). The modprobe blacklist this")
		fmt.Fprintln(os.Stderr, "command writes would be ineffective: there is no module to")
		fmt.Fprintln(os.Stderr, "block from loading. CSM will not pretend to mitigate Copy Fail.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Real options on this kernel:")
		fmt.Fprintln(os.Stderr, "  1. Wait for KernelCare's CVE-2026-31431 patch and apply it")
		fmt.Fprintln(os.Stderr, "     (kcarectl --update). This is the cleanest fix.")
		fmt.Fprintln(os.Stderr, "  2. Apply a seccomp filter to unprivileged service workers")
		fmt.Fprintln(os.Stderr, "     (PHP-FPM, suexec) blocking socket(AF_ALG, ...).")
		fmt.Fprintln(os.Stderr, "  3. Rebuild the kernel with CONFIG_CRYPTO_USER_API_AEAD=n.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "csm audit will continue to flag this host as fail until one")
		fmt.Fprintln(os.Stderr, "of the above is applied.")
		os.Exit(2)
	}

	// Loadable-module kernel: original flow. Write marker, run enforcer.
	if err := checks.WriteAFAlgMarker(); err != nil {
		fmt.Fprintf(os.Stderr, "csm: failed to write marker file %s: %v\n", checks.AFAlgMarkerPath(), err)
		os.Exit(1)
	}

	res, err := checks.EnforceAFAlgBlocked()
	if err != nil {
		fmt.Fprintf(os.Stderr, "csm: enforcement encountered an error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("csm harden --copy-fail")
	fmt.Println("---------------------------")
	fmt.Printf("Marker file:   %s\n", checks.AFAlgMarkerPath())
	fmt.Printf("Marker valid:  %v\n", res.MarkerValid || res.MarkerWritten)
	if len(res.ModulesLoaded) == 0 {
		fmt.Println("Modules:       not loaded")
	} else {
		fmt.Printf("Modules:       %s (unload attempted)\n", strings.Join(res.ModulesLoaded, ", "))
		if res.ModuleUnloaded {
			fmt.Println("Result:        unload succeeded")
		} else {
			fmt.Println("Result:        unload INCOMPLETE; see notes")
		}
	}
	for _, n := range res.Notes {
		fmt.Printf("Note:          %s\n", n)
	}
	fmt.Println()
	fmt.Println("Enforcement is now active. The CSM critical-tier check will")
	fmt.Println("re-apply this policy every 10 minutes if anything drifts.")
	fmt.Println("To re-enable AF_ALG, remove the marker file and reboot.")
}

func hardenUsageString() string {
	return `csm harden - apply targeted hardening policies

Usage: csm harden <policy>

Policies:
  --copy-fail            Mitigate CVE-2026-31431 ("Copy Fail") via the
                         modprobe blacklist. Works only on kernels where
                         algif_aead is a loadable module. Refuses on
                         kernels with CONFIG_CRYPTO_USER_API_AEAD=y.

  --copy-fail-seccomp    Interim Copy Fail mitigation for kernels where
                         AF_ALG aead is built in. Writes systemd drop-ins
                         that apply RestrictAddressFamilies=~AF_ALG to the
                         web/PHP-FPM/cron/mail units that spawn untrusted
                         user code, then reload-or-restarts each. Roll back
                         with --remove.

These commands are operator-driven: they modify system state. Run once
per host (or include in your provisioning playbook). After it runs, the
hardening audit recognizes the mitigation and reports pass.
`
}
