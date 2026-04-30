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
	default:
		fmt.Fprintf(os.Stderr, "Unknown harden subcommand: %s\n", os.Args[2])
		fmt.Fprint(os.Stderr, hardenUsageString())
		os.Exit(1)
	}
}

func runHardenCopyFail() {
	// Write the marker first so EnforceAFAlgBlocked sees an existing marker
	// rather than triggering advisory mode. Subsequent calls (CLI re-runs
	// or the periodic check) are idempotent.
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
			fmt.Println("Result:        unload INCOMPLETE — see notes")
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
  --copy-fail    Mitigate CVE-2026-31431 ("Copy Fail") by blacklisting
                 algif_aead and af_alg in /etc/modprobe.d/ and unloading
                 the modules. Idempotent. The CSM daemon then enforces
                 this policy on every critical-tier tick.

This command is operator-driven: it modifies system state. Run it once
per host (or include it in your provisioning playbook). After it runs,
the daemon's periodic enforcement keeps the policy active.
`
}
