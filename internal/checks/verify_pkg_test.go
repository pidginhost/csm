package checks

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
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

func TestVerifyRPMIntegrityCommandErrorOutputNotResolved(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		runContext: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return []byte("rpm: package passwd is not installed\n"), errors.New("exit 1")
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("rpm_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if res.Checked || res.Resolved {
		t.Fatalf("rpm error output must not verify resolved, got %+v", res)
	}
}

func TestVerifyRPMIntegrityManifestLikeErrorOutputNotResolved(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		runContext: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return []byte("......... not a verifier report\n"), errors.New("exit 1")
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("rpm_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if res.Checked || res.Resolved {
		t.Fatalf("manifest-like error output must not verify resolved, got %+v", res)
	}
}

func TestVerifyRPMIntegrityConfigOnlyOutputResolvesTarget(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		runContext: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return []byte("S.5...... c /etc/passwd\n"), errors.New("exit 1")
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("rpm_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if !res.Checked || !res.Resolved {
		t.Fatalf("config-only output should resolve this target, got %+v", res)
	}
}

func TestVerifyRPMIntegrityTimeoutNotResolved(t *testing.T) {
	oldCmd := cmdExec
	oldTimeout := pkgVerifyTimeout
	pkgVerifyTimeout = time.Nanosecond
	SetCmdRunner(&mockCmd{
		runContext: func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
			<-ctx.Done()
			return nil, nil
		},
	})
	t.Cleanup(func() {
		pkgVerifyTimeout = oldTimeout
		SetCmdRunner(oldCmd)
	})

	res := VerifyFinding("rpm_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if res.Checked || res.Resolved {
		t.Fatalf("rpm timeout must not verify resolved, got %+v", res)
	}
}

func TestVerifyPkgIntegrityRejectsUnsafePackageNames(t *testing.T) {
	for _, checkType := range []string{"rpm_integrity", "dpkg_integrity"} {
		for _, pkg := range []string{"evil; rm -rf", "-rf", "../x", "bad name"} {
			t.Run(checkType+"/"+pkg, func(t *testing.T) {
				old := cmdExec
				calls := 0
				SetCmdRunner(&mockCmd{
					lookPath: func(string) (string, error) {
						calls++
						return "", nil
					},
					runContext: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
						calls++
						return nil, nil
					},
				})
				t.Cleanup(func() { SetCmdRunner(old) })

				msg := fmt.Sprintf("Modified system binary or library: /usr/bin/x (package: %s)", pkg)
				res := VerifyFinding(checkType, msg, "")
				if res.Checked || res.Resolved {
					t.Fatalf("unsafe package name should not auto-verify, got %+v", res)
				}
				if calls != 0 {
					t.Fatalf("package verifier must not exec with unsafe package name, got %d calls", calls)
				}
			})
		}
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

func TestVerifyDpkgIntegrityDebsumsOtherFileResolved(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		lookPath: func(string) (string, error) { return "/usr/bin/debsums", nil },
		runContext: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			if name == "debsums" {
				return []byte("/usr/bin/somethingelse\n"), errors.New("exit 2")
			}
			return nil, errors.New("unexpected " + name)
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("dpkg_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if !res.Checked || !res.Resolved {
		t.Fatalf("debsums should resolve when another file is reported, got %+v", res)
	}
}

func TestVerifyDpkgIntegrityDebsumsErrorOutputNotResolved(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		lookPath: func(string) (string, error) { return "/usr/bin/debsums", nil },
		runContext: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			if name == "debsums" {
				return []byte("debsums: package passwd is not installed\n"), errors.New("exit 2")
			}
			return nil, errors.New("unexpected " + name)
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("dpkg_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if res.Checked || res.Resolved {
		t.Fatalf("debsums error output must not verify resolved, got %+v", res)
	}
}

func TestVerifyDpkgIntegrityDebsumsCommandFailureNotResolved(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		lookPath: func(string) (string, error) { return "/usr/bin/debsums", nil },
		runContext: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			if name == "debsums" {
				return nil, errors.New("debsums failed")
			}
			return nil, errors.New("unexpected " + name)
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("dpkg_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if res.Checked || res.Resolved {
		t.Fatalf("debsums failure must not verify resolved, got %+v", res)
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

func TestVerifyDpkgIntegrityDpkgVerifyStillModifiedUnresolved(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		lookPath: func(string) (string, error) { return "", errors.New("no debsums") },
		runContext: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			if name == "dpkg" {
				return []byte("??5??????  /usr/bin/passwd\n"), errors.New("exit 1")
			}
			return nil, errors.New("unexpected " + name)
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("dpkg_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if !res.Checked || res.Resolved {
		t.Fatalf("dpkg --verify still-modified should verify unresolved, got %+v", res)
	}
}

func TestVerifyDpkgIntegrityDpkgVerifyOtherFileResolved(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		lookPath: func(string) (string, error) { return "", errors.New("no debsums") },
		runContext: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			if name == "dpkg" {
				return []byte("??5??????  /usr/bin/somethingelse\n"), errors.New("exit 1")
			}
			return nil, errors.New("unexpected " + name)
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("dpkg_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if !res.Checked || !res.Resolved {
		t.Fatalf("dpkg --verify should resolve when another file is reported, got %+v", res)
	}
}

func TestVerifyDpkgIntegrityDpkgVerifyErrorOutputNotResolved(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		lookPath: func(string) (string, error) { return "", errors.New("no debsums") },
		runContext: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			if name == "dpkg" {
				return []byte("dpkg-query: package 'passwd' is not installed\n"), errors.New("exit 1")
			}
			return nil, errors.New("unexpected " + name)
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("dpkg_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if res.Checked || res.Resolved {
		t.Fatalf("dpkg --verify error output must not verify resolved, got %+v", res)
	}
}

func TestVerifyDpkgIntegrityDpkgVerifyCommandFailureNotResolved(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{
		lookPath: func(string) (string, error) { return "", errors.New("no debsums") },
		runContext: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			if name == "dpkg" {
				return nil, errors.New("dpkg failed")
			}
			return nil, errors.New("unexpected " + name)
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("dpkg_integrity", "Modified system binary or library: /usr/bin/passwd (package: passwd)", "")
	if res.Checked || res.Resolved {
		t.Fatalf("dpkg --verify failure must not verify resolved, got %+v", res)
	}
}
