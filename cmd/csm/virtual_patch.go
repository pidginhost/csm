package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

var (
	virtualPatchLoadConfig = loadConfigLite
	virtualPatchEUID       = os.Geteuid
	virtualPatchTimeout    = 30 * time.Minute
	virtualPatchScan       = func(ctx context.Context, cfg *config.Config) []alert.Finding {
		return checks.CheckExposedFiles(ctx, cfg, nil)
	}
	virtualPatchApply = checks.VirtualPatchExposedFindings
)

// runVirtualPatch is the operator-triggered ("manual" mode) entry point for
// virtual-patching web-exposed files. It re-scans document roots to re-confirm
// reachability, then previews (default) or applies (--apply) an .htaccess
// "Require all denied" rule per confirmed exposure. Reversible: originals are
// backed up under the quarantine pre_clean dir.
//
// Usage: csm virtual-patch [--apply]
func runVirtualPatch() {
	if code := runVirtualPatchCommand(os.Args[2:], os.Stderr); code != 0 {
		os.Exit(code)
	}
}

func runVirtualPatchCommand(args []string, stderr io.Writer) int {
	apply := false
	for _, a := range args {
		switch a {
		case "--apply":
			apply = true
		case "-h", "--help":
			_, _ = fmt.Fprint(stderr, "usage: csm virtual-patch [--apply]\n\n"+
				"Re-scan document roots and deny HTTP access to confirmed web-exposed files.\n"+
				"Without --apply it only previews. Requires auto_response.virtual_patch_exposed_files\n"+
				"to be set to manual or auto.\n")
			return 0
		default:
			fmt.Fprintf(stderr, "unknown flag %q (try --apply)\n", a)
			return 1
		}
	}

	if virtualPatchEUID() != 0 {
		fmt.Fprintln(stderr, "csm virtual-patch must run as root")
		return 1
	}
	cfg := virtualPatchLoadConfig()
	if cfg.VirtualPatchMode() == config.VirtualPatchOff {
		fmt.Fprintln(stderr, "auto_response.virtual_patch_exposed_files is off; set it to manual or auto to use this command")
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), virtualPatchTimeout)
	defer cancel()

	fmt.Fprintln(stderr, "Scanning document roots for web-exposed files (this can take several minutes)...")
	findings := virtualPatchScan(ctx, cfg)

	// Findings returned before cancellation were individually confirmed by the
	// reachability probe and remain safe to apply. Report the incomplete scan
	// after processing them so operators get both protection and a nonzero exit.
	actions := virtualPatchApply(cfg, findings, apply)

	mode := "PREVIEW (no changes written; pass --apply to enforce)"
	if apply {
		mode = "APPLY"
	}
	fmt.Fprintf(stderr, "\n%s: %d web-exposed finding(s), %d action(s)\n", mode, len(findings), len(actions))
	applied := 0
	failed := 0
	for _, a := range actions {
		fmt.Fprintf(stderr, "  - %s\n", a.Message)
		switch {
		case strings.HasPrefix(a.Message, "VIRTUAL-PATCH: denied"):
			applied++
		case strings.HasPrefix(a.Message, "VIRTUAL-PATCH failed:"):
			failed++
		}
	}
	if apply && applied > 0 {
		fmt.Fprintln(stderr, "\nRollback records saved under the quarantine pre_clean dir; revert via the quarantine-restore UI/API.")
	}
	if ctx.Err() != nil {
		fmt.Fprintf(stderr, "\nScan incomplete: %v; confirmed partial results above were still processed.\n", ctx.Err())
		return 1
	}
	if failed > 0 {
		return 1
	}
	return 0
}
