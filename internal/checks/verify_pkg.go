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
var pkgVerifyTimeout = 30 * time.Second

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

type packageVerifyOutputState struct {
	targetFlagged bool
	sawReport     bool
	sawUnknown    bool
}

// verifyManifestLineFlagsFile reports whether an rpm -V / dpkg --verify output
// line marks the target file as size/checksum-modified (mirrors the detector:
// skip config/doc, require S or 5, require an executable or library).
func verifyManifestLineFlagsFile(line, file string) (targetFlagged, recognized bool) {
	flags, got, ok := parseManifestVerifyLine(line)
	if !ok {
		return false, false
	}
	if !manifestVerifyLineHasPackagePath(line, got) {
		return false, false
	}
	if strings.Contains(line, " c ") || strings.Contains(line, " d ") {
		return false, true
	}
	if !strings.Contains(flags, "S") && !strings.Contains(flags, "5") {
		return false, true
	}
	return got == file && looksExecutableOrLibrary(got), true
}

func manifestVerifyLineHasPackagePath(line, got string) bool {
	if strings.HasPrefix(got, "/") {
		return true
	}
	fields := strings.Fields(strings.TrimSpace(line[9:]))
	if len(fields) != 2 || (fields[0] != "c" && fields[0] != "d") {
		return false
	}
	return strings.HasPrefix(fields[1], "/")
}

func parseManifestVerifyLine(line string) (flags, file string, ok bool) {
	if len(line) < 10 {
		return "", "", false
	}
	flags = line[:9]
	for _, ch := range flags {
		if !strings.ContainsRune(".?SM5DLUGTP", ch) {
			return "", "", false
		}
	}
	file = strings.TrimSpace(line[9:])
	if file == "" {
		return "", "", false
	}
	return flags, file, true
}

func manifestOutputState(out []byte, file string) packageVerifyOutputState {
	var state packageVerifyOutputState
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		targetFlagged, recognized := verifyManifestLineFlagsFile(line, file)
		if !recognized {
			state.sawUnknown = true
			continue
		}
		state.sawReport = true
		if targetFlagged {
			state.targetFlagged = true
		}
	}
	return state
}

func debsumsOutputState(out []byte, file string) packageVerifyOutputState {
	var state packageVerifyOutputState
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		got := strings.TrimSpace(line)
		if got == "" {
			continue
		}
		if !strings.HasPrefix(got, "/") {
			state.sawUnknown = true
			continue
		}
		state.sawReport = true
		if got == file && looksExecutableOrLibrary(got) {
			state.targetFlagged = true
		}
	}
	return state
}

func resolvePkgVerifyOutput(state packageVerifyOutputState, file, verifier string) VerifyResult {
	if state.targetFlagged {
		return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("%s is still reported as modified", file)}
	}
	if state.sawReport && !state.sawUnknown {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("%s is no longer reported as modified", file)}
	}
	return VerifyResult{Checked: false, Detail: fmt.Sprintf("could not parse %s output (try again, or run an account scan)", verifier)}
}

func pkgVerifyTimedOut(ctx context.Context, verifier string) (VerifyResult, bool) {
	if ctx.Err() == nil {
		return VerifyResult{}, false
	}
	return VerifyResult{Checked: false, Detail: fmt.Sprintf("%s timed out (try again, or run an account scan)", verifier)}, true
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
	if res, timedOut := pkgVerifyTimedOut(ctx, "rpm -V"); timedOut {
		return res
	}
	if strings.TrimSpace(string(out)) == "" {
		if err == nil {
			return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("package %s verifies clean", pkg)}
		}
		return VerifyResult{Checked: false, Detail: "could not run rpm -V (try again, or run an account scan)"}
	}
	return resolvePkgVerifyOutput(manifestOutputState(out, file), file, "rpm -V")
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
		if res, timedOut := pkgVerifyTimedOut(ctx, "debsums"); timedOut {
			return res
		}
		if strings.TrimSpace(string(out)) == "" {
			if err == nil {
				return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("package %s verifies clean", pkg)}
			}
			return VerifyResult{Checked: false, Detail: "could not run debsums (try again, or run an account scan)"}
		}
		return resolvePkgVerifyOutput(debsumsOutputState(out, file), file, "debsums")
	}

	out, err := cmdExec.RunContext(ctx, "dpkg", "--verify", pkg)
	if res, timedOut := pkgVerifyTimedOut(ctx, "dpkg --verify"); timedOut {
		return res
	}
	if strings.TrimSpace(string(out)) == "" {
		if err == nil {
			return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("package %s verifies clean", pkg)}
		}
		return VerifyResult{Checked: false, Detail: "could not run dpkg --verify (try again, or run an account scan)"}
	}
	return resolvePkgVerifyOutput(manifestOutputState(out, file), file, "dpkg --verify")
}
