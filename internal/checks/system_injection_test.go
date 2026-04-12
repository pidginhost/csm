package checks

import (
	"context"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func TestCheckKernelModulesNormal(t *testing.T) {
	dir := t.TempDir()
	// Create a fake /proc/modules as a real file for os.Open
	modFile := dir + "/modules"
	_ = os.WriteFile(modFile, []byte("ext4 720896 1 - Live 0xffffffffa0000000\nnfsd 458752 11 - Live 0xffffffffa1000000\n"), 0644)

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/proc/modules" {
				return os.Open(modFile)
			}
			return nil, os.ErrNotExist
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := CheckKernelModules(context.Background(), &config.Config{}, store)
	// First run = baseline, no findings expected
	if len(findings) != 0 {
		t.Errorf("first run (baseline) should produce 0 findings, got %d", len(findings))
	}
}

func TestCheckKernelModulesMissingProc(t *testing.T) {
	withMockOS(t, &mockOS{})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := CheckKernelModules(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("missing /proc/modules should produce 0, got %d", len(findings))
	}
}

// Test internal checkRPMPackageIntegrity directly to bypass platform detection.

func TestCheckRPMPackageIntegrityClean(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			return []byte(""), nil
		},
	})

	findings := checkRPMPackageIntegrity([]string{"openssh-server"})
	if len(findings) != 0 {
		t.Errorf("clean should produce 0, got %d", len(findings))
	}
}

func TestCheckRPMPackageIntegrityModified(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			return []byte("S.5....T.  /usr/sbin/sshd\n"), nil
		},
	})

	findings := checkRPMPackageIntegrity([]string{"openssh-server"})
	if len(findings) == 0 {
		t.Fatal("modified sshd should produce a finding")
	}
	if findings[0].Check != "rpm_integrity" {
		t.Errorf("check = %q", findings[0].Check)
	}
}

func TestCheckDebianPackageIntegrityModified(t *testing.T) {
	withMockCmd(t, &mockCmd{
		lookPath: func(name string) (string, error) {
			if name == "debsums" {
				return "/usr/bin/debsums", nil
			}
			return "", os.ErrNotExist
		},
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			return []byte("/usr/sbin/sshd\n"), nil
		},
	})

	findings := checkDebianPackageIntegrity([]string{"openssh-server"})
	if len(findings) == 0 {
		t.Fatal("modified binary should produce a finding")
	}
}
