package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
)

// The sshd change detector hashed only the root sshd_config while the
// settings parser followed Include, so a drop-in flipping PermitRootLogin to
// yes left the root hash unchanged: no finding, and the dangerous value was
// silently written into the baseline.
func TestCheckSSHDConfigDetectsIncludedDropInChange(t *testing.T) {
	cfgPath, st := testSSHDConfigStore(t, `Include sshd_config.d/*.conf
PasswordAuthentication no
X11Forwarding no
`)
	dropDir := filepath.Join(filepath.Dir(cfgPath), "sshd_config.d")
	if err := os.MkdirAll(dropDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dropIn := filepath.Join(dropDir, "10-root.conf")
	writeSSHDConfig(t, dropIn, "PermitRootLogin no\n")

	if findings := CheckSSHDConfig(context.Background(), nil, st); len(findings) != 0 {
		t.Fatalf("initial baseline findings = %v, want none", findings)
	}

	writeSSHDConfig(t, dropIn, "PermitRootLogin yes\n")

	findings := CheckSSHDConfig(context.Background(), nil, st)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want the PermitRootLogin alert", findings)
	}
	if findings[0].Severity != alert.Critical || findings[0].Message != "PermitRootLogin changed to 'yes' in sshd_config" {
		t.Fatalf("finding = %+v, want Critical PermitRootLogin change", findings[0])
	}
}

// A drop-in that changes without touching a dangerous setting still counts
// as a modification of the effective sshd configuration.
func TestCheckSSHDConfigReportsIncludedDropInModified(t *testing.T) {
	cfgPath, st := testSSHDConfigStore(t, `Include sshd_config.d/*.conf
PermitRootLogin without-password
PasswordAuthentication no
`)
	dropDir := filepath.Join(filepath.Dir(cfgPath), "sshd_config.d")
	if err := os.MkdirAll(dropDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dropIn := filepath.Join(dropDir, "50-forward.conf")
	writeSSHDConfig(t, dropIn, "X11Forwarding no\n")

	if findings := CheckSSHDConfig(context.Background(), nil, st); len(findings) != 0 {
		t.Fatalf("initial baseline findings = %v, want none", findings)
	}
	writeSSHDConfig(t, dropIn, "X11Forwarding yes\n")

	findings := CheckSSHDConfig(context.Background(), nil, st)
	if len(findings) != 1 || findings[0].Message != "sshd_config modified" {
		t.Fatalf("findings = %v, want one generic sshd_config change", findings)
	}
}

// Includes inside Match blocks are connection-scoped, so their directives
// must not alter the global settings view. They are still part of the loaded
// configuration and must participate in the change-detection digest.
func TestCheckSSHDConfigDetectsMatchScopedIncludeChange(t *testing.T) {
	cfgPath, st := testSSHDConfigStore(t, `PasswordAuthentication no
Match User alice
    Include sshd_config.d/alice.conf
`)
	dropDir := filepath.Join(filepath.Dir(cfgPath), "sshd_config.d")
	if err := os.MkdirAll(dropDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dropIn := filepath.Join(dropDir, "alice.conf")
	writeSSHDConfig(t, dropIn, "X11Forwarding no\n")

	if findings := CheckSSHDConfig(context.Background(), nil, st); len(findings) != 0 {
		t.Fatalf("initial baseline findings = %v, want none", findings)
	}
	writeSSHDConfig(t, dropIn, "PermitRootLogin yes\n")

	findings := CheckSSHDConfig(context.Background(), nil, st)
	if len(findings) != 1 || findings[0].Message != "sshd_config modified" {
		t.Fatalf("findings = %v, want one generic Match-scoped config change", findings)
	}
}

func TestCheckSSHDConfigDetectsIncludedFileRemoval(t *testing.T) {
	cfgPath, st := testSSHDConfigStore(t, "Include sshd_config.d/*.conf\nPasswordAuthentication no\n")
	dropDir := filepath.Join(filepath.Dir(cfgPath), "sshd_config.d")
	if err := os.MkdirAll(dropDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dropIn := filepath.Join(dropDir, "20-extra.conf")
	writeSSHDConfig(t, dropIn, "X11Forwarding no\n")
	if findings := CheckSSHDConfig(context.Background(), nil, st); len(findings) != 0 {
		t.Fatalf("initial baseline findings = %v, want none", findings)
	}
	if err := os.Remove(dropIn); err != nil {
		t.Fatal(err)
	}

	findings := CheckSSHDConfig(context.Background(), nil, st)
	if len(findings) != 1 || findings[0].Message != "sshd_config modified" {
		t.Fatalf("findings = %v, want one removal change", findings)
	}
}

// Parsing and hashing the files in separate reads can pair old effective
// settings with new file bytes. The new digest then suppresses the next run,
// so a dangerous setting change receives only a generic alert. The digest
// must describe the exact bytes the parser consumed.
func TestCheckSSHDConfigDigestMatchesParsedBytes(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.conf")
	newPath := filepath.Join(dir, "new.conf")
	writeSSHDConfig(t, oldPath, "PermitRootLogin no\nPasswordAuthentication no\n")
	writeSSHDConfig(t, newPath, "PermitRootLogin yes\nPasswordAuthentication no\n")

	st, err := state.Open(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	oldConfigPath := sshdConfigPath
	sshdConfigPath = "/etc/ssh/sshd_config"
	t.Cleanup(func() { sshdConfigPath = oldConfigPath })

	parsedPath := oldPath
	hashedPath := oldPath
	withMockOS(t, &mockOS{
		open:     func(string) (*os.File, error) { return os.Open(parsedPath) },
		readFile: func(string) ([]byte, error) { return os.ReadFile(hashedPath) },
	})
	if got := CheckSSHDConfig(context.Background(), nil, st); len(got) != 0 {
		t.Fatalf("baseline findings = %+v", got)
	}

	// Simulate the file being replaced after parsing but before the old
	// second-pass hash read.
	hashedPath = newPath
	if got := CheckSSHDConfig(context.Background(), nil, st); len(got) != 0 {
		t.Fatalf("incoherent parser/hash snapshot produced findings: %+v", got)
	}

	parsedPath = newPath
	findings := CheckSSHDConfig(context.Background(), nil, st)
	if len(findings) != 1 || findings[0].Severity != alert.Critical ||
		findings[0].Message != "PermitRootLogin changed to 'yes' in sshd_config" {
		t.Fatalf("coherent dangerous change findings = %+v", findings)
	}
}
