package checks

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// pkgVerifyTimeout bounds the synchronous package-manager re-check a Re-check
// click runs.
const pkgVerifyTimeout = 30 * time.Second

// pkgNameRe is the safe character set for a package name passed as an argument
// to rpm/dpkg/debsums. Findings carry CSM-generated package names, but the
// re-check still validates before exec so a malformed name can never inject.
var pkgNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:~-]*$`)

// parsePkgIntegrityFinding extracts the file and package from an
// rpm_integrity / dpkg_integrity message:
// "Modified system binary or library: <file> (package: <pkg>)".
func parsePkgIntegrityFinding(message string) (file, pkg string, ok bool) {
	rest, ok := strings.CutPrefix(message, "Modified system binary or library: ")
	if !ok {
		return "", "", false
	}
	const sep = " (package: "
	i := strings.LastIndex(rest, sep)
	if i < 0 || !strings.HasSuffix(rest, ")") {
		return "", "", false
	}
	file = strings.TrimSpace(rest[:i])
	pkg = strings.TrimSpace(rest[i+len(sep) : len(rest)-1])
	if file == "" || pkg == "" {
		return "", "", false
	}
	return file, pkg, true
}

// verifyManifestLineFlagsFile reports whether an rpm -V / dpkg --verify output
// line marks the target file as size/checksum-modified (mirrors the detector:
// skip config/doc, require S or 5, require an executable or library).
func verifyManifestLineFlagsFile(line, file string) bool {
	if len(line) < 9 {
		return false
	}
	if strings.Contains(line, " c ") || strings.Contains(line, " d ") {
		return false
	}
	flags := line[:9]
	if !strings.Contains(flags, "S") && !strings.Contains(flags, "5") {
		return false
	}
	got := strings.TrimSpace(line[9:])
	return got == file && looksExecutableOrLibrary(got)
}

func manifestOutputStillFlagsFile(out []byte, file string) bool {
	for _, line := range strings.Split(string(out), "\n") {
		if verifyManifestLineFlagsFile(line, file) {
			return true
		}
	}
	return false
}

// verifyRPMIntegrity re-runs `rpm -V <pkg>` and resolves the finding when the
// flagged file is no longer reported as modified (or the whole package verifies
// clean). Read-only, bounded; any command failure returns Checked:false so a
// real tampered binary is never auto-cleared.
func verifyRPMIntegrity(message string) VerifyResult {
	file, pkg, ok := parsePkgIntegrityFinding(message)
	if !ok {
		return VerifyResult{Checked: false, Detail: "could not parse the package finding"}
	}
	if !pkgNameRe.MatchString(pkg) {
		return VerifyResult{Checked: false, Detail: "package name in finding is not auto-verifiable"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), pkgVerifyTimeout)
	defer cancel()
	// rpm -V exits non-zero when files are modified; treat output, not exit
	// code, as the signal.
	out, err := cmdExec.RunContext(ctx, "rpm", "-V", pkg)
	if len(out) == 0 {
		if err == nil {
			return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("package %s verifies clean", pkg)}
		}
		return VerifyResult{Checked: false, Detail: "could not run rpm -V (try again, or run an account scan)"}
	}
	if manifestOutputStillFlagsFile(out, file) {
		return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("%s is still reported as modified", file)}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("%s is no longer reported as modified", file)}
}

// verifyDpkgIntegrity re-runs debsums (preferred) or `dpkg --verify` for the
// package and resolves the finding when the flagged file is no longer reported
// as modified. Same safety contract as verifyRPMIntegrity.
func verifyDpkgIntegrity(message string) VerifyResult {
	file, pkg, ok := parsePkgIntegrityFinding(message)
	if !ok {
		return VerifyResult{Checked: false, Detail: "could not parse the package finding"}
	}
	if !pkgNameRe.MatchString(pkg) {
		return VerifyResult{Checked: false, Detail: "package name in finding is not auto-verifiable"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), pkgVerifyTimeout)
	defer cancel()

	if _, err := cmdExec.LookPath("debsums"); err == nil {
		// debsums -c prints one modified file path per line (exit 2 on mismatch).
		out, err := cmdExec.RunContext(ctx, "debsums", "-c", pkg)
		if len(out) == 0 {
			if err == nil {
				return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("package %s verifies clean", pkg)}
			}
			return VerifyResult{Checked: false, Detail: "could not run debsums (try again, or run an account scan)"}
		}
		for _, line := range strings.Split(string(out), "\n") {
			got := strings.TrimSpace(line)
			if got == file && looksExecutableOrLibrary(got) {
				return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("%s is still reported as modified", file)}
			}
		}
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("%s is no longer reported as modified", file)}
	}

	out, err := cmdExec.RunContext(ctx, "dpkg", "--verify", pkg)
	if len(out) == 0 {
		if err == nil {
			return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("package %s verifies clean", pkg)}
		}
		return VerifyResult{Checked: false, Detail: "could not run dpkg --verify (try again, or run an account scan)"}
	}
	if manifestOutputStillFlagsFile(out, file) {
		return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("%s is still reported as modified", file)}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("%s is no longer reported as modified", file)}
}
