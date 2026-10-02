package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPamFailureHookWidensSpacedControls(t *testing.T) {
	stack := "auth [success = 1 default = ignore] pam_permit.so\n" +
		"auth requisite pam_deny.so\nauth required pam_permit.so\n"
	want := "auth [success = 2 default = ignore] pam_permit.so\n" +
		pamTestFailureHook + "\nauth requisite pam_deny.so\nauth required pam_permit.so\n"
	got, err := pamInsertFailureHook([]byte(stack))
	if err != nil || string(got) != want {
		t.Fatalf("insert: %v\ngot:\n%s\nwant:\n%s", err, got, want)
	}
	restored, removed, err := pamRemoveManagedLines(got)
	if err != nil || removed != 1 || string(restored) != stack {
		t.Fatalf("remove: count=%d err=%v\ngot:\n%s", removed, err, restored)
	}
}

func TestPamFailureHookRefusesJumpOverflow(t *testing.T) {
	for _, jump := range []string{"2147483647", "4294967295", "9223372036854775807"} {
		stack := "auth [success=" + jump + " default=ignore] pam_permit.so\nauth requisite pam_deny.so\n"
		if got, err := pamInsertFailureHook([]byte(stack)); !errors.Is(err, errPAMMalformedLine) {
			t.Fatalf("jump=%s: err=%v; want malformed jump\n%s", jump, err, got)
		}
	}
}

func TestPamFailureHookWidensControlWhitespace(t *testing.T) {
	stack := "auth [success\v=\f1 default=ignore] pam_permit.so\n" +
		"auth requisite pam_deny.so\nauth required pam_permit.so\n"
	want := "auth [success\v=\f2 default=ignore] pam_permit.so\n" +
		pamTestFailureHook + "\nauth requisite pam_deny.so\nauth required pam_permit.so\n"
	got, err := pamInsertFailureHook([]byte(stack))
	if err != nil || string(got) != want {
		t.Fatalf("insert: %v\ngot: %q\nwant: %q", err, got, want)
	}
}

func TestPamFailureHookRecognizesBracketedArgument(t *testing.T) {
	stack := "auth sufficient pam_unix.so\n" +
		"auth optional pam_csm.so [authfail]\nauth required pam_deny.so\n"
	path := filepath.Join(t.TempDir(), "password-auth")
	writePAMFile(t, path, stack)
	changed, err := pamEnsureFailureHook(path, false)
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v; want existing hook", changed, err)
	}
	if got := readPAMTestFile(t, path); got != stack {
		t.Fatalf("existing hook changed:\n%s", got)
	}
	if pamDirectivePresent([]byte(stack), "auth") {
		t.Fatal("bracketed authfail counted as a success hook")
	}
	if pamHasFailureHook([]byte("auth optional pam_csm.so [unused authfail]\n")) {
		t.Fatal("multiword argument counted as authfail")
	}
}

func TestPamFailureHookRestoresEndJumps(t *testing.T) {
	for _, jump := range []string{"1", "2", "9"} {
		t.Run(jump, func(t *testing.T) {
			stack := "auth required pam_permit.so\n" +
				"auth [success=" + jump + " default=ignore] pam_permit.so\n" +
				"auth required pam_deny.so\n"
			got, err := pamInsertFailureHook([]byte(stack))
			if err != nil {
				t.Fatal(err)
			}
			restored, removed, err := pamRemoveManagedLines(got)
			if err != nil || removed != 1 || string(restored) != stack {
				t.Fatalf("remove: count=%d err=%v\ngot:\n%s\nwant:\n%s", removed, err, restored, stack)
			}
		})
	}
}

func TestPamRemoveFailureHookDoesNotWriteZeroJump(t *testing.T) {
	stack := "auth required pam_permit.so\n" +
		"auth [success=1 default=ignore] pam_permit.so\n" +
		pamTestFailureHook + "\nauth required pam_permit.so\n"
	want := "auth required pam_permit.so\n" +
		"auth [success=ignore default=ignore] pam_permit.so\nauth required pam_permit.so\n"
	got, removed, err := pamRemoveManagedLines([]byte(stack))
	if err != nil || removed != 1 || string(got) != want {
		t.Fatalf("remove: count=%d err=%v\ngot:\n%s\nwant:\n%s", removed, err, got, want)
	}
}

func TestPamFailureHookRefusesUnprovableControlFlow(t *testing.T) {
	for name, stack := range map[string]string{
		"adjacent reset action":   "auth required pam_deny.so\nauth [success=resetdefault=ignore] pam_permit.so\nauth required pam_permit.so\n",
		"include can jump out":    "auth include other-auth\nauth requisite pam_deny.so\nauth required pam_permit.so\n",
		"at include can jump out": "@include other-auth\nauth requisite pam_deny.so\nauth required pam_permit.so\n",
		"reset can recover deny":  "auth required pam_deny.so\nauth [success=reset default=ignore] pam_permit.so\nauth required pam_permit.so\n",
		"include can reset deny":  "auth required pam_deny.so\nauth include other-auth\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "common-auth")
			writePAMFile(t, path, stack)
			changed, err := pamEnsureFailureHook(path, false)
			if err == nil || !pamStackRefusal(err) || changed {
				t.Fatalf("changed=%v err=%v; want safe refusal", changed, err)
			}
			if got := readPAMTestFile(t, path); got != stack {
				t.Fatalf("refusal changed file:\n%s", got)
			}
			if backups, _ := filepath.Glob(path + ".csm-backup-*"); len(backups) != 0 {
				t.Fatalf("refusal created backups: %v", backups)
			}
		})
	}
}

func TestPamRemoveFailureHookRefusesEscapingInclude(t *testing.T) {
	stack := "auth include other-auth\n" + pamTestFailureHook +
		"\nauth requisite pam_deny.so\nauth required pam_permit.so\n"
	path := filepath.Join(t.TempDir(), "common-auth")
	writePAMFile(t, path, stack)
	removed, err := pamRemoveLines(path)
	if !errors.Is(err, errPAMJumpAcrossInclude) || removed != 0 {
		t.Fatalf("count=%d err=%v; want include refusal", removed, err)
	}
	if got := readPAMTestFile(t, path); got != stack {
		t.Fatalf("refusal changed file:\n%s", got)
	}
}

func TestPamStackErrorsDoNotExposeArguments(t *testing.T) {
	stack := "auth [success=1 default=ignore pam_example.so operator-option\n"
	_, err := pamInsertFailureHook([]byte(stack))
	if !errors.Is(err, errPAMMalformedLine) {
		t.Fatalf("err=%v; want malformed line", err)
	}
	if strings.Contains(err.Error(), "pam_example.so") || strings.Contains(err.Error(), "operator-option") {
		t.Fatalf("error exposes configuration arguments: %v", err)
	}
}

func TestPamFailureHookIgnoresJumpsOfOtherTypes(t *testing.T) {
	stack := "session [success=2 default=ignore] pam_permit.so\n" +
		"session include other-session\n" +
		"auth sufficient pam_unix.so\nauth required pam_deny.so\n" +
		"session required pam_permit.so\n"
	got, err := pamInsertFailureHook([]byte(stack))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(stack, "auth required pam_deny.so", pamTestFailureHook+"\nauth required pam_deny.so", 1)
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	restored, removed, err := pamRemoveManagedLines(got)
	if err != nil || removed != 1 || string(restored) != stack {
		t.Fatalf("remove: count=%d err=%v\ngot:\n%s", removed, err, restored)
	}
}

func TestPamRemoveLinesLeavesUnmanagedSyntaxAlone(t *testing.T) {
	for _, stack := range []string{
		"auth required pam_unix.so \\\n  nullok\n",
		"auth required\n",
	} {
		path := filepath.Join(t.TempDir(), "sshd")
		writePAMFile(t, path, stack)
		removed, err := pamRemoveLines(path)
		if err != nil || removed != 0 {
			t.Fatalf("remove: count=%d err=%v; want no-op", removed, err)
		}
		if got := readPAMTestFile(t, path); got != stack {
			t.Fatalf("unmanaged file changed:\n%s", got)
		}
	}
}

func TestPamRemoveLinesCanEmptyAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sshd")
	writePAMFile(t, path, "auth optional pam_csm.so # managed-by-csm\n"+
		"session optional pam_csm.so # managed-by-csm\n")
	removed, err := pamRemoveLines(path)
	if err != nil || removed != 2 {
		t.Fatalf("remove: count=%d err=%v", removed, err)
	}
	if got := readPAMTestFile(t, path); got != "" {
		t.Fatalf("removed hooks left extra content: %q", got)
	}
}

func TestPamInstallStacksReportsEveryRefusal(t *testing.T) {
	dir := t.TempDir()
	safe := filepath.Join(dir, "common-auth")
	writePAMFile(t, safe, pamTestDebianStack)
	target := filepath.Join(dir, "authselect-password-auth")
	writePAMFile(t, target, pamTestRHELStack)
	linked := filepath.Join(dir, "password-auth")
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	for _, dryRun := range []bool{true, false} {
		var out strings.Builder
		err := pamInstallStacks(&out, nil, []string{safe, linked}, dryRun)
		if !errors.Is(err, errPAMSymlinkedStack) {
			t.Fatalf("dryRun=%v: err=%v; want symlink refusal\n%s", dryRun, err, out.String())
		}
	}
}
