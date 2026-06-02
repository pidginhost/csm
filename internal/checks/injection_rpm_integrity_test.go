package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// execStatFileInfo presents a regular, executable file so looksExecutableOrLibrary
// reports it. The mode&0111 branch short-circuits before any Open is needed.
type execStatFileInfo struct{ name string }

func (e execStatFileInfo) Name() string     { return e.name }
func (execStatFileInfo) Size() int64        { return 4096 }
func (execStatFileInfo) Mode() os.FileMode  { return 0o755 }
func (execStatFileInfo) ModTime() time.Time { return time.Time{} }
func (execStatFileInfo) IsDir() bool        { return false }
func (execStatFileInfo) Sys() interface{}   { return nil }

// withExecutableFiles makes every Stat return an executable regular file, so a
// package-verify mismatch is treated as a tampered binary regardless of path.
func withExecutableFiles(t *testing.T) {
	t.Helper()
	withMockOS(t, &mockOS{stat: func(name string) (os.FileInfo, error) {
		return execStatFileInfo{name: name}, nil
	}})
}

// --- checkRPMPackageIntegrity ------------------------------------------

func TestCheckRPMPackageIntegrityEmptyOutputNoFindings(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) {
			return []byte(""), nil
		},
	})
	if got := checkRPMPackageIntegrity([]string{"openssh-server"}); got != nil {
		t.Errorf("empty rpm -V output should yield no findings, got %d", len(got))
	}
}

func TestCheckRPMPackageIntegrityCommandFailureSkips(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) {
			return nil, errors.New("rpm not installed")
		},
	})
	if got := checkRPMPackageIntegrity([]string{"openssh-server"}); got != nil {
		t.Errorf("command failure should yield no findings, got %d", len(got))
	}
}

func TestCheckRPMPackageIntegrityModifiedBinaryEmitsCritical(t *testing.T) {
	withExecutableFiles(t)
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) {
			// rpm -V output: "S.5......" flags + "/usr/bin/passwd"
			return []byte("S.5......  /usr/bin/passwd\n"), nil
		},
	})
	got := checkRPMPackageIntegrity([]string{"shadow-utils"})
	if len(got) != 1 {
		t.Fatalf("expected 1 critical finding, got %d", len(got))
	}
	if got[0].Severity != alert.Critical || got[0].Check != "rpm_integrity" {
		t.Errorf("unexpected finding: %+v", got[0])
	}
	if !strings.Contains(got[0].Message, "/usr/bin/passwd") {
		t.Errorf("message should reference modified file: %s", got[0].Message)
	}
}

func TestCheckRPMPackageIntegritySkipsConfigFiles(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) {
			// "S.5...... c /etc/sshd/sshd_config" — the " c " marker tags it as a
			// config file, which must be skipped per the verifier's design.
			return []byte("S.5......  c /etc/sshd/sshd_config\n"), nil
		},
	})
	if got := checkRPMPackageIntegrity([]string{"openssh-server"}); got != nil {
		t.Errorf("config file should be skipped, got %d findings", len(got))
	}
}

func TestCheckRPMPackageIntegritySkipsNonExecutableFiles(t *testing.T) {
	// A non-executable, non-ELF packaged file (e.g. package-manager state) is
	// not reported even when its checksum changed.
	withMockOS(t, &mockOS{stat: func(string) (os.FileInfo, error) { return fakeFileInfo{}, nil }})
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) {
			return []byte("S.5......  /var/lib/something\n"), nil
		},
	})
	if got := checkRPMPackageIntegrity([]string{"openssh-server"}); got != nil {
		t.Errorf("non-executable file should be skipped, got %d findings", len(got))
	}
}

// A tampered shared library outside the legacy /usr/bin allowlist must now be
// reported -- this is the path-allowlist bypass the fix closes.
func TestCheckRPMPackageIntegrityReportsLibraryOutsideBinDirs(t *testing.T) {
	withExecutableFiles(t)
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) {
			return []byte("S.5......  /usr/lib64/libcrypto.so.3\n"), nil
		},
	})
	got := checkRPMPackageIntegrity([]string{"openssl-libs"})
	if len(got) != 1 || !strings.Contains(got[0].Message, "/usr/lib64/libcrypto.so.3") {
		t.Fatalf("tampered library outside bin dirs must be reported, got %+v", got)
	}
}

func TestCheckRPMPackageIntegrityReportsNonExecutableELFLibrary(t *testing.T) {
	lib := filepath.Join(t.TempDir(), "libcrypto.so.3")
	if err := os.WriteFile(lib, []byte("\x7fELF\x02\x01\x01"), 0o644); err != nil {
		t.Fatal(err)
	}
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) {
			return []byte("S.5......  " + lib + "\n"), nil
		},
	})
	got := checkRPMPackageIntegrity([]string{"openssl-libs"})
	if len(got) != 1 || !strings.Contains(got[0].Message, lib) {
		t.Fatalf("tampered 0644 ELF library must be reported, got %+v", got)
	}
}

// --- checkDebianPackageIntegrity --------------------------------------

func TestCheckDebianPackageIntegrityPrefersDebsumsWhenAvailable(t *testing.T) {
	debsumsCalled, dpkgCalled := false, false
	withMockCmd(t, &mockCmd{
		lookPath: func(name string) (string, error) {
			if name == "debsums" {
				return "/usr/bin/debsums", nil
			}
			return "", errors.New("not found")
		},
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			switch name {
			case "debsums":
				debsumsCalled = true
			case "dpkg":
				dpkgCalled = true
			}
			return []byte(""), nil
		},
	})
	_ = checkDebianPackageIntegrity([]string{"sudo"})
	if !debsumsCalled {
		t.Error("debsums should have been called when present")
	}
	if dpkgCalled {
		t.Error("dpkg should NOT be called when debsums is available")
	}
}

func TestCheckDebianPackageIntegrityFallsBackToDpkgVerify(t *testing.T) {
	dpkgCalled := false
	withMockCmd(t, &mockCmd{
		lookPath: func(string) (string, error) {
			return "", errors.New("debsums not installed")
		},
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			if name == "dpkg" {
				dpkgCalled = true
			}
			return []byte(""), nil
		},
	})
	_ = checkDebianPackageIntegrity([]string{"sudo"})
	if !dpkgCalled {
		t.Error("dpkg should have been called when debsums is missing")
	}
}

// --- checkDpkgVerify ---------------------------------------------------

func TestCheckDpkgVerifyParsesMd5MismatchFlag(t *testing.T) {
	withExecutableFiles(t)
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) {
			return []byte("??5??????   /usr/bin/passwd\n"), nil
		},
	})
	got := checkDpkgVerify([]string{"passwd"})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Check != "dpkg_integrity" || got[0].Severity != alert.Critical {
		t.Errorf("unexpected finding: %+v", got[0])
	}
}

func TestCheckDpkgVerifySkipsConfigFiles(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) {
			// " c " marker tags this as a config file → skipped.
			return []byte("??5??????  c /etc/passwd\n"), nil
		},
	})
	if got := checkDpkgVerify([]string{"passwd"}); got != nil {
		t.Errorf("config file should be skipped, got %d findings", len(got))
	}
}

func TestCheckDpkgVerifySkipsLinesWithoutSor5Flag(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) {
			// Only a 'T' (mtime) flag — not interesting per the design.
			return []byte("?T???????   /usr/bin/passwd\n"), nil
		},
	})
	if got := checkDpkgVerify([]string{"passwd"}); got != nil {
		t.Errorf("non-S/5 flag lines should be skipped, got %d findings", len(got))
	}
}

func TestCheckDpkgVerifySkipsNonExecutableFiles(t *testing.T) {
	// Package-manager metadata (not executable) is not reported.
	withMockOS(t, &mockOS{stat: func(string) (os.FileInfo, error) { return fakeFileInfo{}, nil }})
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) {
			return []byte("??5??????   /var/lib/dpkg/info/x.list\n"), nil
		},
	})
	if got := checkDpkgVerify([]string{"sudo"}); got != nil {
		t.Errorf("non-executable file should be skipped, got %d findings", len(got))
	}
}

func TestCheckDpkgVerifyReportsNonExecutableELFLibrary(t *testing.T) {
	lib := filepath.Join(t.TempDir(), "libssl.so.3")
	if err := os.WriteFile(lib, []byte("\x7fELF\x02\x01\x01"), 0o644); err != nil {
		t.Fatal(err)
	}
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) {
			return []byte("??5??????   " + lib + "\n"), nil
		},
	})
	got := checkDpkgVerify([]string{"libssl3"})
	if len(got) != 1 || !strings.Contains(got[0].Message, lib) {
		t.Fatalf("tampered 0644 ELF library must be reported, got %+v", got)
	}
}

// --- CheckRPMIntegrity dispatcher --------------------------------------

func TestCheckRPMIntegrityNonLinuxFamilyReturnsNil(t *testing.T) {
	// platform.Detect on macOS/dev return OSFamily that's neither RHEL nor
	// Debian — function should fall through to the nil return.
	got := CheckRPMIntegrity(context.Background(), &config.Config{}, nil)
	if got != nil {
		t.Errorf("non-Linux family should yield nil, got %d findings", len(got))
	}
}
