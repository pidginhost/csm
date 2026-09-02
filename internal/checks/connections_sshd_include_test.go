package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
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
