package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// wpVerifyAllowedRoots bounds where a WordPress re-check may run wp-cli. It is a
// var so tests can redirect under t.TempDir(); production stays at /home.
var wpVerifyAllowedRoots = []string{"/home"}

// wpVerifyTimeout bounds the synchronous wp-cli re-scan a Re-check click runs.
const wpVerifyTimeout = 30 * time.Second

// findingDetailPath extracts the "Path: <dir>" value emitted in a finding's
// Details (outdated_plugins and the WordPress checks record the install path
// there). Returns "" when no such line is present.
func findingDetailPath(details string) string {
	for _, line := range strings.Split(details, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "Path:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

func wpChecksumLineHasExtraneousCoreFile(line string) bool {
	return strings.Contains(line, "should not exist") && !strings.Contains(line, "error_log")
}

// verifyOutdatedPlugins re-inventories a single WordPress site with wp-cli (run
// as the site owner) and resolves the finding when no active plugin still has
// an available update. It is heavier than the file re-checks but read-only and
// bounded by wpVerifyTimeout. Any failure to re-scan returns Checked:false so a
// finding is never falsely cleared on a transient wp-cli error.
func verifyOutdatedPlugins(details string) VerifyResult {
	wpPath := findingDetailPath(details)
	if wpPath == "" {
		return VerifyResult{Checked: false, Detail: "could not determine the WordPress path from the finding"}
	}
	clean, _, exists, err := readOnlyFixPath(wpPath, wpVerifyAllowedRoots)
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if !exists {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("WordPress install no longer exists: %s", clean)}
	}

	wpConfig, info, exists, err := readOnlyFixPath(filepath.Join(clean, "wp-config.php"), wpVerifyAllowedRoots)
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if !exists {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("WordPress install no longer present: %s", clean)}
	}
	if !info.Mode().IsRegular() {
		return VerifyResult{Checked: false, Detail: "wp-config.php path is not a regular file; not auto-verifiable"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), wpVerifyTimeout)
	defer cancel()
	site, err := inventoryWPSiteForVerify(ctx, wpConfig)
	if err != nil {
		return VerifyResult{Checked: false, Detail: fmt.Sprintf("could not re-scan plugins (try again, or run an account scan): %v", err)}
	}

	if n := countOutdatedActivePlugins(site, store.Global()); n > 0 {
		return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("%d active plugin(s) still outdated", n)}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: "no active plugins are outdated anymore"}
}

// verifyWPCoreIntegrity re-runs `wp core verify-checksums` for one install and
// resolves the finding when no extraneous core file ("should not exist")
// remains -- mirroring CheckWPCore, which only flags those lines. It is
// read-only and bounded by wpVerifyTimeout. To avoid ever clearing a real
// compromise it resolves only when verification is clean or the install is
// gone; any wp-cli error (including modified files with no remaining
// extra-file line) returns Checked:false.
func verifyWPCoreIntegrity(details string) VerifyResult {
	wpPath := findingDetailPath(details)
	if wpPath == "" {
		return VerifyResult{Checked: false, Detail: "could not determine the WordPress path from the finding"}
	}
	clean, _, exists, err := readOnlyFixPath(wpPath, wpVerifyAllowedRoots)
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if !exists {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("WordPress install no longer exists: %s", clean)}
	}
	_, info, exists, err := readOnlyFixPath(filepath.Join(clean, "wp-config.php"), wpVerifyAllowedRoots)
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if !exists {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("WordPress install no longer present: %s", clean)}
	}
	if !info.Mode().IsRegular() {
		return VerifyResult{Checked: false, Detail: "wp-config.php path is not a regular file; not auto-verifiable"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), wpVerifyTimeout)
	defer cancel()
	// Mirrors CheckWPCore: run as root with --allow-root (not su as the user).
	// Args are passed directly (no shell), so the sanitized path cannot inject.
	out, err := cmdExec.RunContext(ctx, "wp", "core", "verify-checksums", "--path="+clean, "--allow-root")
	if err == nil {
		return VerifyResult{Checked: true, Resolved: true, Detail: "WordPress core checksums verify clean"}
	}
	if len(out) == 0 {
		return VerifyResult{Checked: false, Detail: "could not run wp core verify-checksums (try again, or run an account scan)"}
	}
	for _, line := range strings.Split(string(out), "\n") {
		if wpChecksumLineHasExtraneousCoreFile(line) {
			return VerifyResult{Checked: true, Resolved: false, Detail: "WordPress core still has extraneous files"}
		}
	}
	// Non-zero exit with no remaining "should not exist" line: could be a
	// modified-file note or a wp-cli error we cannot tell apart. Do not resolve.
	return VerifyResult{Checked: false, Detail: "could not confirm core integrity (verify-checksums reported other issues); re-run or use an account scan"}
}
