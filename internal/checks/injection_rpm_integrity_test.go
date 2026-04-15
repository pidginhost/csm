package checks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

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

func TestCheckRPMPackageIntegritySkipsNonBinaryPaths(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) {
			return []byte("S.5......  /var/lib/something\n"), nil
		},
	})
	if got := checkRPMPackageIntegrity([]string{"openssh-server"}); got != nil {
		t.Errorf("non-binary path should be skipped, got %d findings", len(got))
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

func TestCheckDpkgVerifySkipsNonCriticalPaths(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) {
			return []byte("??5??????   /var/lib/dpkg/info/x.list\n"), nil
		},
	})
	if got := checkDpkgVerify([]string{"sudo"}); got != nil {
		t.Errorf("non-critical path should be skipped, got %d findings", len(got))
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
