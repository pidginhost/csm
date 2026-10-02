package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const pamTestFailureHook = "auth     optional   pam_csm.so authfail # managed-by-csm"

// RHEL-family shared stack as shipped without authselect.
const pamTestRHELStack = "#%PAM-1.0\n" +
	"auth        required      pam_env.so\n" +
	"auth        required      pam_faildelay.so delay=2000000\n" +
	"auth        sufficient    pam_unix.so try_first_pass nullok\n" +
	"auth        required      pam_deny.so\n" +
	"\n" +
	"account     required      pam_unix.so\n" +
	"session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid\n" +
	"session     required      pam_unix.so\n"

// Debian-family common-auth as written by pam-auth-update.
const pamTestDebianStack = "auth\t[success=1 default=ignore]\tpam_unix.so nullok\n" +
	"auth\trequisite\t\t\tpam_deny.so\n" +
	"auth\trequired\t\t\tpam_permit.so\n" +
	"auth\toptional\t\t\tpam_cap.so\n"

func TestPamInsertFailureHookRHELGoesBeforeDeny(t *testing.T) {
	got, err := pamInsertFailureHook([]byte(pamTestRHELStack))
	if err != nil {
		t.Fatalf("pamInsertFailureHook: %v", err)
	}
	want := strings.Replace(pamTestRHELStack,
		"auth        required      pam_deny.so\n",
		pamTestFailureHook+"\nauth        required      pam_deny.so\n", 1)
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

// A stack that fails a required module before pam_unix (cPanel adds
// pam_hulk.so there) still reaches pam_deny on every failed login, so the
// hook goes before pam_deny and earlier lines stay untouched.
func TestPamInsertFailureHookKeepsEarlierRequiredModules(t *testing.T) {
	stack := "auth        required      pam_env.so\n" +
		"auth\trequired\tpam_hulk.so\n" +
		"auth        sufficient    pam_unix.so try_first_pass nullok\n" +
		"auth        required      pam_deny.so\n" +
		"auth     optional   pam_csm.so # managed-by-csm\n" +
		"session  optional   pam_csm.so # managed-by-csm\n"
	got, err := pamInsertFailureHook([]byte(stack))
	if err != nil {
		t.Fatalf("pamInsertFailureHook: %v", err)
	}
	want := "auth        required      pam_env.so\n" +
		"auth\trequired\tpam_hulk.so\n" +
		"auth        sufficient    pam_unix.so try_first_pass nullok\n" +
		pamTestFailureHook + "\n" +
		"auth        required      pam_deny.so\n" +
		"auth     optional   pam_csm.so # managed-by-csm\n" +
		"session  optional   pam_csm.so # managed-by-csm\n"
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

// A success jump over pam_deny must also jump over the hook, or a correct
// password would be reported as a failure.
func TestPamInsertFailureHookWidensSuccessJumpOverDeny(t *testing.T) {
	got, err := pamInsertFailureHook([]byte(pamTestDebianStack))
	if err != nil {
		t.Fatalf("pamInsertFailureHook: %v", err)
	}
	want := "auth\t[success=2 default=ignore]\tpam_unix.so nullok\n" +
		pamTestFailureHook + "\n" +
		"auth\trequisite\t\t\tpam_deny.so\n" +
		"auth\trequired\t\t\tpam_permit.so\n" +
		"auth\toptional\t\t\tpam_cap.so\n"
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestPamInsertFailureHookWidensEveryPrimaryJump(t *testing.T) {
	stack := "auth\t[success=2 default=ignore]\tpam_unix.so nullok\n" +
		"auth\t[success=1 default=ignore]\tpam_sss.so use_first_pass\n" +
		"auth\trequisite\t\t\tpam_deny.so\n" +
		"auth\trequired\t\t\tpam_permit.so\n"
	got, err := pamInsertFailureHook([]byte(stack))
	if err != nil {
		t.Fatalf("pamInsertFailureHook: %v", err)
	}
	want := "auth\t[success=3 default=ignore]\tpam_unix.so nullok\n" +
		"auth\t[success=2 default=ignore]\tpam_sss.so use_first_pass\n" +
		pamTestFailureHook + "\n" +
		"auth\trequisite\t\t\tpam_deny.so\n" +
		"auth\trequired\t\t\tpam_permit.so\n"
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

// A jump that lands on pam_deny is a failure path: it must land on the hook.
// Jumps of other PAM types and jumps that start after pam_deny keep their
// counts.
func TestPamInsertFailureHookKeepsJumpsThatDoNotSkipDeny(t *testing.T) {
	stack := "auth [success=ok default=1] pam_succeed_if.so uid >= 1000\n" +
		"auth sufficient pam_unix.so\n" +
		"session [success=1 default=ignore] pam_succeed_if.so service in crond\n" +
		"auth required pam_deny.so\n" +
		"auth [success=1 default=ignore] pam_permit.so\n" +
		"auth optional pam_cap.so\n" +
		"session required pam_unix.so\n"
	got, err := pamInsertFailureHook([]byte(stack))
	if err != nil {
		t.Fatalf("pamInsertFailureHook: %v", err)
	}
	want := "auth [success=ok default=1] pam_succeed_if.so uid >= 1000\n" +
		"auth sufficient pam_unix.so\n" +
		"session [success=1 default=ignore] pam_succeed_if.so service in crond\n" +
		pamTestFailureHook + "\n" +
		"auth required pam_deny.so\n" +
		"auth [success=1 default=ignore] pam_permit.so\n" +
		"auth optional pam_cap.so\n" +
		"session required pam_unix.so\n"
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestPamInsertFailureHookCountsOptionalTypePrefix(t *testing.T) {
	stack := "auth [success=2 default=ignore] pam_unix.so\n" +
		"-auth optional pam_systemd_home.so\n" +
		"auth requisite pam_deny.so\n" +
		"auth required pam_permit.so\n"
	got, err := pamInsertFailureHook([]byte(stack))
	if err != nil {
		t.Fatalf("pamInsertFailureHook: %v", err)
	}
	want := "auth [success=3 default=ignore] pam_unix.so\n" +
		"-auth optional pam_systemd_home.so\n" +
		pamTestFailureHook + "\n" +
		"auth requisite pam_deny.so\n" +
		"auth required pam_permit.so\n"
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestPamInsertFailureHookRefusesUnplaceableStacks(t *testing.T) {
	cases := []struct {
		name  string
		stack string
		want  error
	}{
		{"no deny", "auth sufficient pam_unix.so\nauth required pam_permit.so\n", errPAMNoDenyLine},
		{"commented deny", "auth sufficient pam_unix.so\n# auth required pam_deny.so\n", errPAMNoDenyLine},
		{"optional deny", "auth sufficient pam_unix.so\nauth optional pam_deny.so\n", errPAMNoDenyLine},
		{"two denies", "auth sufficient pam_unix.so\nauth required pam_deny.so\nauth sufficient pam_sss.so\nauth requisite pam_deny.so\n", errPAMSeveralDenyLines},
		{"jump across include", "auth [success=2 default=ignore] pam_unix.so\nauth include other-auth\nauth requisite pam_deny.so\nauth required pam_permit.so\n", errPAMJumpAcrossInclude},
		{"jump across substack", "auth [success=2 default=ignore] pam_unix.so\nauth substack other-auth\nauth requisite pam_deny.so\nauth required pam_permit.so\n", errPAMJumpAcrossInclude},
		{"jump across @include", "auth [success=2 default=ignore] pam_unix.so\n@include other-auth\nauth requisite pam_deny.so\nauth required pam_permit.so\n", errPAMJumpAcrossInclude},
		{"continuation line", "auth sufficient pam_unix.so \\\n  nullok\nauth required pam_deny.so\n", errPAMLineContinuation},
		{"line without module", "auth sufficient pam_unix.so\nauth required\nauth required pam_deny.so\n", errPAMMalformedLine},
		{"unclosed control", "auth [success=1 default=ignore pam_unix.so\nauth requisite pam_deny.so\n", errPAMMalformedLine},
		{"unknown type", "auht sufficient pam_unix.so\nauth required pam_deny.so\n", errPAMMalformedLine},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pamInsertFailureHook([]byte(tc.stack))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v (out:\n%s)", err, tc.want, got)
			}
		})
	}
}

// Includes of other types and auth includes after a requisite deny cannot
// jump across the new hook. An auth include before it could jump out.
func TestPamInsertFailureHookAllowsIncludeOutsideJump(t *testing.T) {
	stack := "session include pre-session\n" +
		"auth [success=1 default=ignore] pam_unix.so\n" +
		"auth requisite pam_deny.so\n" +
		"auth required pam_permit.so\n" +
		"auth include post-auth\n"
	got, err := pamInsertFailureHook([]byte(stack))
	if err != nil {
		t.Fatalf("pamInsertFailureHook: %v", err)
	}
	want := "session include pre-session\n" +
		"auth [success=2 default=ignore] pam_unix.so\n" +
		pamTestFailureHook + "\n" +
		"auth requisite pam_deny.so\n" +
		"auth required pam_permit.so\n" +
		"auth include post-auth\n"
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestPamEnsureFailureHookInstallsOnceWithBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "common-auth")
	writePAMFile(t, path, pamTestDebianStack)

	changed, err := pamEnsureFailureHook(path, false)
	if err != nil || !changed {
		t.Fatalf("first install: changed=%v err=%v", changed, err)
	}
	first := readPAMTestFile(t, path)
	if strings.Count(first, "authfail") != 1 {
		t.Fatalf("want one failure hook:\n%s", first)
	}
	backups, err := filepath.Glob(filepath.Join(dir, "common-auth.csm-backup-*"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups = %v, err %v; want one", backups, err)
	}
	if got := readPAMTestFile(t, backups[0]); got != pamTestDebianStack {
		t.Fatalf("backup holds:\n%s\nwant original", got)
	}

	changed, err = pamEnsureFailureHook(path, false)
	if err != nil || changed {
		t.Fatalf("second install: changed=%v err=%v; want no-op", changed, err)
	}
	if got := readPAMTestFile(t, path); got != first {
		t.Fatalf("second install rewrote file:\n%s", got)
	}
}

// An operator-written failure hook anywhere in the stack counts: a second
// one would report every failure twice.
func TestPamEnsureFailureHookHonorsOperatorHook(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password-auth")
	stack := "auth sufficient pam_unix.so\nauth [default=ignore] /lib64/security/pam_csm.so authfail\nauth required pam_deny.so\n"
	writePAMFile(t, path, stack)

	changed, err := pamEnsureFailureHook(path, false)
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v; want no-op", changed, err)
	}
	if got := readPAMTestFile(t, path); got != stack {
		t.Fatalf("file rewritten:\n%s", got)
	}
}

func TestPamEnsureFailureHookDryRunLeavesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password-auth")
	writePAMFile(t, path, pamTestRHELStack)

	changed, err := pamEnsureFailureHook(path, true)
	if err != nil || !changed {
		t.Fatalf("dry-run: changed=%v err=%v; want pending change", changed, err)
	}
	if got := readPAMTestFile(t, path); got != pamTestRHELStack {
		t.Fatalf("dry-run wrote file:\n%s", got)
	}
}

func TestPamEnsureFailureHookRefusalLeavesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password-auth")
	stack := "auth sufficient pam_unix.so\nauth required pam_permit.so\n"
	writePAMFile(t, path, stack)

	changed, err := pamEnsureFailureHook(path, false)
	if !errors.Is(err, errPAMNoDenyLine) || changed {
		t.Fatalf("changed=%v err=%v; want refusal", changed, err)
	}
	if got := readPAMTestFile(t, path); got != stack {
		t.Fatalf("refused install wrote file:\n%s", got)
	}
	if backups, _ := filepath.Glob(filepath.Join(dir, "password-auth.csm-backup-*")); len(backups) != 0 {
		t.Fatalf("refused install left backups: %v", backups)
	}
}

// authselect owns /etc/pam.d/password-auth through a symlink and rewrites the
// target on its next run, so an edit there would not last.
func TestPamEnsureFailureHookRefusesSymlinkedStack(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "authselect-password-auth")
	writePAMFile(t, target, pamTestRHELStack)
	path := filepath.Join(dir, "password-auth")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	changed, err := pamEnsureFailureHook(path, false)
	if !errors.Is(err, errPAMSymlinkedStack) || changed {
		t.Fatalf("changed=%v err=%v; want symlink refusal", changed, err)
	}
	if got := readPAMTestFile(t, target); got != pamTestRHELStack {
		t.Fatalf("symlink target edited:\n%s", got)
	}
}

func TestPamRemoveLinesRestoresStackByteForByte(t *testing.T) {
	for name, stack := range map[string]string{
		"rhel":   pamTestRHELStack,
		"debian": pamTestDebianStack,
		"sss": "auth\t[success=2 default=ignore]\tpam_unix.so nullok\n" +
			"auth\t[success=1 default=ignore]\tpam_sss.so use_first_pass\n" +
			"auth\trequisite\t\t\tpam_deny.so\n" +
			"auth\trequired\t\t\tpam_permit.so\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "common-auth")
			writePAMFile(t, path, stack)
			if _, err := pamEnsureLines(path, false); err != nil {
				t.Fatal(err)
			}
			if _, err := pamEnsureFailureHook(path, false); err != nil {
				t.Fatal(err)
			}
			removed, err := pamRemoveLines(path)
			if err != nil {
				t.Fatalf("pamRemoveLines: %v", err)
			}
			if removed != 3 {
				t.Fatalf("removed = %d, want 3", removed)
			}
			if got := readPAMTestFile(t, path); got != stack {
				t.Fatalf("uninstall left:\n%s\nwant original:\n%s", got, stack)
			}
		})
	}
}

// A jump that already ran past the end of the stack still does after the
// appended lines go, so uninstall leaves its count as the operator wrote it.
func TestPamRemoveLinesKeepsJumpPastEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password-auth")
	stack := pamTestRHELStack + "session     [success=3 default=ignore] pam_succeed_if.so service in crond quiet\n" +
		"session     required      pam_limits.so\n"
	writePAMFile(t, path, stack)
	if _, err := pamEnsureLines(path, false); err != nil {
		t.Fatal(err)
	}
	if _, err := pamRemoveLines(path); err != nil {
		t.Fatalf("pamRemoveLines: %v", err)
	}
	if got := readPAMTestFile(t, path); got != stack {
		t.Fatalf("uninstall left:\n%s\nwant original:\n%s", got, stack)
	}
}

func TestPamInsertFailureHookKeepsMissingFinalNewline(t *testing.T) {
	got, err := pamInsertFailureHook([]byte("auth sufficient pam_unix.so\nauth required pam_deny.so"))
	if err != nil {
		t.Fatalf("pamInsertFailureHook: %v", err)
	}
	want := "auth sufficient pam_unix.so\n" + pamTestFailureHook + "\nauth required pam_deny.so"
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPamRemoveLinesRefusesJumpAcrossInclude(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "common-auth")
	stack := "auth [success=3 default=ignore] pam_unix.so\n" +
		"auth include other-auth\n" +
		pamTestFailureHook + "\n" +
		"auth requisite pam_deny.so\n" +
		"auth required pam_permit.so\n"
	writePAMFile(t, path, stack)

	if _, err := pamRemoveLines(path); !errors.Is(err, errPAMJumpAcrossInclude) {
		t.Fatalf("err = %v, want %v", err, errPAMJumpAcrossInclude)
	}
	if got := readPAMTestFile(t, path); got != stack {
		t.Fatalf("refused uninstall wrote file:\n%s", got)
	}
}

// The plain hook only drives the success report; a failure hook is not a
// substitute for it in a service file.
func TestPamEnsureLinesDoesNotCountFailureHookAsAuthHook(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd")
	writePAMFile(t, path, "auth optional pam_csm.so authfail\n")

	if _, err := pamEnsureLines(path, false); err != nil {
		t.Fatal(err)
	}
	if got := readPAMTestFile(t, path); !strings.Contains(got, "auth     optional   pam_csm.so # managed-by-csm\n") {
		t.Fatalf("plain auth hook not added:\n%s", got)
	}
}

func TestPamFailureHookState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password-auth")

	writePAMFile(t, path, pamTestRHELStack)
	if got := pamFailureHookState(path); got != "not reported (run csm pam install)" {
		t.Errorf("unhooked = %q", got)
	}
	if _, err := pamEnsureFailureHook(path, false); err != nil {
		t.Fatal(err)
	}
	if got := pamFailureHookState(path); got != "reported" {
		t.Errorf("hooked = %q", got)
	}

	linked := filepath.Join(dir, "linked-auth")
	if err := os.Symlink(path, linked); err != nil {
		t.Fatal(err)
	}
	if got := pamFailureHookState(linked); !strings.HasPrefix(got, "not reported (") || !strings.Contains(got, "symlink") {
		t.Errorf("symlinked = %q", got)
	}
	if got := pamFailureHookState(filepath.Join(dir, "missing")); got != "absent" {
		t.Errorf("missing = %q", got)
	}
}

func TestPamInstallStacksReportsUnreportedFailures(t *testing.T) {
	dir := t.TempDir()
	rhel := filepath.Join(dir, "password-auth")
	debian := filepath.Join(dir, "common-auth")
	writePAMFile(t, rhel, "auth sufficient pam_unix.so\nauth required pam_permit.so\n")

	var out strings.Builder
	err := pamInstallStacks(&out, nil, []string{rhel, debian}, false)
	if !errors.Is(err, errPAMNoDenyLine) {
		t.Fatalf("err = %v, want %v\n%s", err, errPAMNoDenyLine, out.String())
	}
	if !strings.Contains(out.String(), "failed logins") {
		t.Fatalf("output does not name the gap:\n%s", out.String())
	}

	writePAMFile(t, rhel, pamTestRHELStack)
	out.Reset()
	if err := pamInstallStacks(&out, nil, []string{rhel, debian}, false); err != nil {
		t.Fatalf("pamInstallStacks: %v\n%s", err, out.String())
	}
	if got := readPAMTestFile(t, rhel); strings.Count(got, "authfail") != 1 {
		t.Fatalf("failure hook missing:\n%s", got)
	}
}

func TestPamInstallStacksNeedsASharedStack(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	err := pamInstallStacks(&out, nil, []string{filepath.Join(dir, "password-auth")}, false)
	if !errors.Is(err, errPAMNoSharedStack) {
		t.Fatalf("err = %v, want %v\n%s", err, errPAMNoSharedStack, out.String())
	}
}

func readPAMTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test fixture under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
