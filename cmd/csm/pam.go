package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// runPAM dispatches `csm pam <subcommand>`. Subcommands:
//
//	status    - report whether pam_csm.so is installed and which /etc/pam.d
//	            files reference it.
//	install   - copy build/pam/pam_csm.so to the platform's security dir,
//	            append the optional session/auth lines to the standard
//	            PAM service files and place the failed-login hook in the
//	            shared auth stack. Idempotent; refuses to run without a
//	            backup of every file it edits.
//	uninstall - remove the lines added by install and (optionally) the
//	            shipped pam_csm.so binary.
//
// Wraps the privileged side of the "Phase B" PAM rollout. The C source
// and Makefile live under build/pam/; the package install drops the
// compiled .so into /usr/lib/csm/pam/pam_csm.so so this command can
// stage it without re-running gcc on the host.
func runPAM() {
	args := os.Args[2:]
	if len(args) == 0 {
		pamUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "status":
		exitOnError(pamStatus(os.Stdout))
	case "install":
		fs := flag.NewFlagSet("pam install", flag.ExitOnError)
		dryRun := fs.Bool("dry-run", false, "preview the files that would be edited, do not write")
		modulePath := fs.String("module", "", "override the source pam_csm.so path (defaults to /usr/lib/csm/pam/pam_csm.so)")
		_ = fs.Parse(args[1:])
		exitOnError(pamInstall(os.Stdout, *modulePath, *dryRun))
	case "uninstall":
		fs := flag.NewFlagSet("pam uninstall", flag.ExitOnError)
		keepModule := fs.Bool("keep-module", false, "remove only the /etc/pam.d edits, leave pam_csm.so in place")
		_ = fs.Parse(args[1:])
		exitOnError(pamUninstall(os.Stdout, *keepModule))
	case "--help", "-h", "help":
		pamUsage()
	default:
		fmt.Fprintf(os.Stderr, "csm pam: unknown subcommand %q\n\n", args[0])
		pamUsage()
		os.Exit(2)
	}
}

func pamUsage() {
	fmt.Fprintln(os.Stderr, `csm pam - PAM hook management

Usage: csm pam <subcommand> [options]

Subcommands:
  status               Report pam_csm.so install state and the /etc/pam.d files referencing it.
  install [--dry-run] [--module <path>]
                       Copy pam_csm.so into the platform security dir, append
                       "session optional pam_csm.so" + "auth optional pam_csm.so"
                       to the standard PAM service files, and add
                       "auth optional pam_csm.so authfail" before pam_deny.so in
                       the shared auth stack. Exits non-zero when failed logins
                       cannot be reported. --dry-run only previews.
  uninstall [--keep-module]
                       Remove the lines this command added. --keep-module leaves
                       the shipped pam_csm.so binary in place.

WARNING: Authentication runs through PAM. A malformed edit can lock you
out. install creates a timestamped .csm-backup of every file before
touching it. If you lose access, revert by renaming the backup back.`)
}

// pamServiceFiles lists the service-specific /etc/pam.d entries we touch.
// They get the success hook only.
var pamServiceFiles = []string{
	"/etc/pam.d/sshd",
	"/etc/pam.d/su",
	"/etc/pam.d/sudo",
}

// pamSharedAuthStacks lists the auth stacks the remote login services
// include. They get the success hook and the failed-login hook; one failure
// hook there reports each failed attempt once, whichever service ran it.
var pamSharedAuthStacks = []string{
	"/etc/pam.d/password-auth", // RHEL
	"/etc/pam.d/common-auth",   // Debian
}

const (
	// pamMarker is appended as the trailing comment of every line this
	// command writes so uninstall can find them again without grep
	// false positives against operator-authored lines.
	pamMarker = "# managed-by-csm"
)

// pamModuleSources lists candidate on-disk locations for pam_csm.so in
// priority order. The first that exists is used as the install source.
// rpm/deb packages drop the module under /usr/lib/csm/pam/; binary
// installs via scripts/deploy.sh extract csm-assets.tar.gz into
// /opt/csm/, which lands the module under /opt/csm/pam/.
var pamModuleSources = []string{
	"/usr/lib/csm/pam/pam_csm.so",
	"/opt/csm/pam/pam_csm.so",
}

func defaultPAMModuleSource() (string, error) {
	for _, p := range pamModuleSources {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("pam_csm.so not found in any of %v; rebuild from build/pam or reinstall the CSM package", pamModuleSources)
}

// pamSecurityDirs lists candidate destination directories in priority
// order. The first that exists on the host wins.
var pamSecurityDirs = []string{
	"/lib64/security",
	"/usr/lib64/security",
	"/lib/x86_64-linux-gnu/security",
	"/usr/lib/x86_64-linux-gnu/security",
	"/lib/aarch64-linux-gnu/security",
	"/usr/lib/aarch64-linux-gnu/security",
	"/lib/security",
}

func resolvePAMSecurityDir() (string, error) {
	for _, dir := range pamSecurityDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no PAM security directory found; install libpam first")
}

// pamStatus prints the current install state. Returns nil on success;
// surfaces errors so operators can pipe `csm pam status; echo $?` into
// a healthcheck.
func pamStatus(w io.Writer) error {
	if runtime.GOOS != "linux" {
		fmt.Fprintln(w, "csm pam: PAM management only available on Linux hosts")
		return nil
	}
	dir, err := resolvePAMSecurityDir()
	if err != nil {
		fmt.Fprintf(w, "PAM security dir: NOT FOUND (%v)\n", err)
	} else {
		modPath := filepath.Join(dir, "pam_csm.so")
		if _, err := os.Stat(modPath); err == nil {
			fmt.Fprintf(w, "Module:           installed at %s\n", modPath)
		} else {
			fmt.Fprintf(w, "Module:           NOT installed (looked under %s)\n", dir)
		}
	}
	for _, path := range pamServiceFiles {
		fmt.Fprintf(w, "%-32s: %s\n", path, pamFileState(path))
	}
	for _, path := range pamSharedAuthStacks {
		fmt.Fprintf(w, "%-32s: %s\n", path, pamFileState(path))
		if _, err := os.Lstat(path); err == nil {
			fmt.Fprintf(w, "%-32s  failed logins: %s\n", "", pamFailureHookState(path))
		}
	}
	return nil
}

func pamFileState(path string) string {
	data, err := os.ReadFile(path) // #nosec G304 -- caller controls path; only iterates the fixed PAM file lists.
	if err != nil {
		if os.IsNotExist(err) {
			return "absent"
		}
		return fmt.Sprintf("error reading: %v", err)
	}
	if pamHasActiveCSMHook(data) {
		return "hooked"
	}
	return "not hooked"
}

// pamInstall copies the module and edits each pam.d service file that
// exists. Refuses if the source module is missing. Every edit creates a
// timestamped backup so operators can roll back without losing host
// access.
func pamInstall(w io.Writer, srcOverride string, dryRun bool) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("csm pam install: only supported on Linux hosts (got %s)", runtime.GOOS)
	}
	src := srcOverride
	if src == "" {
		resolved, err := defaultPAMModuleSource()
		if err != nil {
			return err
		}
		src = resolved
	}
	if info, err := os.Stat(src); err != nil {
		return fmt.Errorf("pam_csm.so not found at %s: %w (rebuild from build/pam or reinstall the CSM package)", src, err)
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("pam_csm.so source is not a regular file: %s", src)
	}
	dir, err := resolvePAMSecurityDir()
	if err != nil {
		return err
	}
	dst := filepath.Join(dir, "pam_csm.so")

	if dryRun {
		fmt.Fprintf(w, "[dry-run] would copy %s -> %s\n", src, dst)
	} else {
		if err := copyFileMode(src, dst, 0o755); err != nil {
			return fmt.Errorf("copying module: %w", err)
		}
		fmt.Fprintf(w, "installed %s -> %s\n", src, dst)
	}

	stacksErr := pamInstallStacks(w, pamServiceFiles, pamSharedAuthStacks, dryRun)
	if !dryRun {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Test from a SECOND terminal before closing this one. If SSH login")
		fmt.Fprintln(w, "or sudo breaks, the backups end in .csm-backup-<timestamp>.")
	}
	return stacksErr
}

// pamInstallStacks hooks the service files and the shared auth stacks. It
// returns an error when no shared stack ends up reporting failed logins,
// after every other edit is done: brute-force detection depends on them.
func pamInstallStacks(w io.Writer, services, shared []string, dryRun bool) error {
	for _, path := range services {
		if _, err := pamInstallSuccessHook(w, path, dryRun); err != nil {
			return err
		}
	}
	reported := false
	var gaps []error
	for _, path := range shared {
		present, err := pamInstallSuccessHook(w, path, dryRun)
		if err != nil {
			return err
		}
		if !present {
			continue
		}
		changed, err := pamEnsureFailureHook(path, dryRun)
		switch {
		case pamStackRefusal(err):
			fmt.Fprintf(w, "WARNING: failed logins are not reported through %s: %v\n", path, err)
			gaps = append(gaps, fmt.Errorf("%s: %w", path, err))
			continue
		case err != nil:
			return fmt.Errorf("editing %s: %w", path, err)
		case dryRun && changed:
			fmt.Fprintf(w, "[dry-run] would add the failed-login hook to %s\n", path)
		case changed:
			fmt.Fprintf(w, "added the failed-login hook to %s\n", path)
		default:
			fmt.Fprintf(w, "no change to %s (failed-login hook present)\n", path)
		}
		reported = true
	}
	if reported {
		return nil
	}
	if len(gaps) == 0 {
		return fmt.Errorf("failed logins are not reported to CSM: %w (looked for %s)", errPAMNoSharedStack, strings.Join(shared, ", "))
	}
	return fmt.Errorf("failed logins are not reported to CSM: %w", errors.Join(gaps...))
}

// pamInstallSuccessHook adds the plain auth and session lines to path. It
// reports whether the file exists.
func pamInstallSuccessHook(w io.Writer, path string, dryRun bool) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(w, "skip %s (not present)\n", path)
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		fmt.Fprintf(w, "skip %s (not a regular file)\n", path)
		return false, nil
	}
	changed, err := pamEnsureLines(path, dryRun)
	if err != nil {
		return false, fmt.Errorf("editing %s: %w", path, err)
	}
	switch {
	case dryRun && changed:
		fmt.Fprintf(w, "[dry-run] would add pam_csm.so lines to %s\n", path)
	case changed:
		fmt.Fprintf(w, "added pam_csm.so lines to %s\n", path)
	default:
		fmt.Fprintf(w, "no change to %s (already hooked)\n", path)
	}
	return true, nil
}

// pamEnsureLines appends the two CSM-managed PAM directives to path if
// they are not already present. Returns whether the file was modified.
// In dry-run mode the file is left untouched.
func pamEnsureLines(path string, dryRun bool) (bool, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from the fixed PAM file lists.
	if err != nil {
		return false, err
	}
	wants := []pamDirective{
		{kind: "auth", line: "auth     optional   pam_csm.so " + pamMarker},
		{kind: "session", line: "session  optional   pam_csm.so " + pamMarker},
	}
	missing := []string{}
	for _, want := range wants {
		// Any active pam_csm.so reference for the same PAM type counts as
		// already hooked; do not stack a second copy because an operator
		// used different spacing or control flags.
		if pamDirectivePresent(data, want.kind) {
			continue
		}
		missing = append(missing, want.line)
	}
	if len(missing) == 0 {
		return false, nil
	}
	if dryRun {
		return true, nil
	}
	backup, err := writePAMBackup(path, data)
	if err != nil {
		return false, err
	}
	out := bytes.NewBuffer(make([]byte, 0, len(data)+128))
	if _, err := out.Write(data); err != nil {
		return false, err
	}
	if !bytes.HasSuffix(data, []byte("\n")) {
		out.WriteByte('\n')
	}
	for _, line := range missing {
		out.WriteString(line)
		out.WriteByte('\n')
	}
	// #nosec G306 -- /etc/pam.d service files are standard 0644 so libpam
	// can read them under every PAM-aware stack; tightening to 0600 would
	// break authentication on services that resolve PAM as non-root.
	// Atomic write so sshd / login / cron parsing the file mid-edit
	// always see either the old or the new contents, never a truncated
	// or partially-written file that would break authentication.
	if err := writeFileAtomic(path, out.Bytes(), 0o644); err != nil {
		return false, fmt.Errorf("writing %s after backup %s: %w", path, backup, err)
	}
	return true, nil
}

// pamUninstall reverses install. Leaves backups in place so operators
// can restore manually if pamUninstall itself misbehaves.
func pamUninstall(w io.Writer, keepModule bool) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("csm pam uninstall: only supported on Linux hosts (got %s)", runtime.GOOS)
	}
	for _, path := range append(append([]string(nil), pamServiceFiles...), pamSharedAuthStacks...) {
		removed, err := pamRemoveLines(path)
		if err != nil {
			return fmt.Errorf("editing %s: %w", path, err)
		}
		if removed > 0 {
			fmt.Fprintf(w, "removed %d pam_csm.so line(s) from %s\n", removed, path)
		}
	}
	if keepModule {
		fmt.Fprintln(w, "--keep-module: leaving pam_csm.so in place")
		return nil
	}
	dir, dirErr := resolvePAMSecurityDir()
	if dirErr != nil {
		// PAM security dir is gone (libpam uninstalled, for example);
		// surface the absence to the operator but treat it as success
		// because there is nothing left to clean up.
		fmt.Fprintf(w, "PAM security dir not found (%v); skipping module removal\n", dirErr)
		return nil
	}
	target := filepath.Join(dir, "pam_csm.so")
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s: %w", target, err)
	}
	fmt.Fprintf(w, "removed %s\n", target)
	return nil
}

func pamRemoveLines(path string) (int, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from the fixed PAM file lists.
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	out, removed, err := pamRemoveManagedLines(data)
	if err != nil {
		return 0, err
	}
	if removed == 0 {
		return 0, nil
	}
	backup, err := writePAMBackup(path, data)
	if err != nil {
		return 0, err
	}
	// #nosec G306 -- /etc/pam.d service files are standard 0644; see the
	// matching annotation in pamEnsureLines above.
	// Atomic write so a concurrent PAM-aware service never reads a
	// half-written file during uninstall.
	if err := writeFileAtomic(path, out, 0o644); err != nil {
		return 0, fmt.Errorf("writing %s after backup %s: %w", path, backup, err)
	}
	return removed, nil
}

func copyFileMode(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src) // #nosec G304 -- src is the packaged module or an explicit root-only CLI override.
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	tmp, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".csm-staging-*") // #nosec G304 -- temp file is created inside the resolved PAM security dir.
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	removeTmp = false
	return nil
}

type pamDirective struct {
	kind string
	line string
}

func pamHasActiveCSMHook(data []byte) bool {
	for _, raw := range strings.Split(string(data), "\n") {
		line, err := parsePAMLine(raw)
		if err == nil && line != nil && filepath.Base(line.module) == "pam_csm.so" {
			return true
		}
	}
	return false
}

// pamDirectivePresent reports an active success hook of the given type. The
// failure hook does not count: it never reports a successful login.
func pamDirectivePresent(data []byte, kind string) bool {
	for _, raw := range strings.Split(string(data), "\n") {
		line, err := parsePAMLine(raw)
		if err == nil && line != nil && line.kind == kind &&
			filepath.Base(line.module) == "pam_csm.so" && !line.hasArg(pamFailureHookArg) {
			return true
		}
	}
	return false
}

func pamManagedLine(line string) bool {
	return strings.Contains(line, pamMarker) && strings.Contains(line, "pam_csm.so")
}

func writePAMBackup(path string, data []byte) (string, error) {
	base := fmt.Sprintf("%s.csm-backup-%s", path, time.Now().UTC().Format("20060102T150405Z"))
	for i := 0; i < 100; i++ {
		backup := base
		if i > 0 {
			backup = fmt.Sprintf("%s-%02d", base, i)
		}
		f, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- backup path is derived from a fixed PAM service path.
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("creating backup %s: %w", backup, err)
		}
		if _, err := f.Write(data); err != nil {
			_ = f.Close()
			return "", fmt.Errorf("writing backup %s: %w", backup, err)
		}
		if err := f.Close(); err != nil {
			return "", fmt.Errorf("closing backup %s: %w", backup, err)
		}
		return backup, nil
	}
	return "", fmt.Errorf("creating backup %s: too many timestamp collisions", base)
}

func exitOnError(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
