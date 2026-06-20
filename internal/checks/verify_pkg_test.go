package checks

import (
	"context"
	"errors"
	"testing"
)

func TestParsePkgIntegrityFinding(t *testing.T) {
	file, pkg, ok := parsePkgIntegrityFinding("Modified system binary or library: /usr/bin/passwd (package: passwd)")
	if !ok || file != "/usr/bin/passwd" || pkg != "passwd" {
		t.Fatalf("parse = (%q, %q, %v)", file, pkg, ok)
	}
	if _, _, ok := parsePkgIntegrityFinding("something else"); ok {
		t.Error("unrelated message should not parse")
	}
}

func TestVerifyRPMIntegrityCleanResolved(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "rpm" && args[0] == "-V" && args[1] == "passwd" {
				return nil, nil // clean: exit 0, no output
			}
			return nil, errors.New("unexpected")
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("rpm_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if !res.Checked || !res.Resolved {
		t.Fatalf("clean package should verify resolved, got %+v", res)
	}
}

func TestVerifyRPMIntegrityFileGoneResolved(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		runContext: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			// Some other file modified, but not our target.
			return []byte("S.5....T.  /usr/bin/somethingelse\n"), errors.New("exit 1")
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("rpm_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if !res.Checked || !res.Resolved {
		t.Fatalf("target no longer modified should verify resolved, got %+v", res)
	}
}

func TestVerifyRPMIntegrityStillModifiedUnresolved(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		runContext: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return []byte("S.5....T.  /usr/bin/passwd\n"), errors.New("exit 1")
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("rpm_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if !res.Checked || res.Resolved {
		t.Fatalf("still-modified file should verify unresolved, got %+v", res)
	}
}

func TestVerifyRPMIntegrityCommandFailureNotResolved(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		runContext: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return nil, errors.New("rpm: command not found")
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("rpm_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if res.Checked || res.Resolved {
		t.Fatalf("rpm failure must not verify resolved, got %+v", res)
	}
}

func TestVerifyPkgIntegrityRejectsUnsafePackageName(t *testing.T) {
	old := cmdExec
	calls := 0
	SetCmdRunner(&mockCmd{
		runContext: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			calls++
			return nil, nil
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("rpm_integrity", "Modified system binary or library: /usr/bin/x (package: evil; rm -rf)", "")
	if res.Checked || res.Resolved {
		t.Fatalf("unsafe package name should not auto-verify, got %+v", res)
	}
	if calls != 0 {
		t.Fatalf("rpm must not run with an unsafe package name, got %d calls", calls)
	}
}

func TestVerifyDpkgIntegrityDebsumsStillModifiedUnresolved(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		lookPath: func(string) (string, error) { return "/usr/bin/debsums", nil },
		runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "debsums" {
				return []byte("/usr/bin/passwd\n"), errors.New("exit 2")
			}
			return nil, errors.New("unexpected " + name)
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("dpkg_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if !res.Checked || res.Resolved {
		t.Fatalf("debsums still-modified should verify unresolved, got %+v", res)
	}
}

func TestVerifyDpkgIntegrityDpkgVerifyCleanResolved(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		lookPath: func(string) (string, error) { return "", errors.New("no debsums") },
		runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "dpkg" {
				return nil, nil // clean
			}
			return nil, errors.New("unexpected " + name)
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("dpkg_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if !res.Checked || !res.Resolved {
		t.Fatalf("dpkg --verify clean should verify resolved, got %+v", res)
	}
}
