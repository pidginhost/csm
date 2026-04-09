package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/state"
)

func TestCheckSSHDConfigIgnoresCommentedDefaults(t *testing.T) {
	cfgPath, st := testSSHDConfigStore(t, `PermitRootLogin without-password
#PermitRootLogin yes
#PasswordAuthentication yes
PasswordAuthentication no
X11Forwarding no
`)

	if findings := CheckSSHDConfig(context.Background(), nil, st); len(findings) != 0 {
		t.Fatalf("initial baseline findings = %v, want none", findings)
	}

	writeSSHDConfig(t, cfgPath, `PermitRootLogin without-password
#PermitRootLogin yes
#PasswordAuthentication yes
PasswordAuthentication no
X11Forwarding yes
`)

	findings := CheckSSHDConfig(context.Background(), nil, st)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want 1 generic change alert", findings)
	}
	if findings[0].Message != "sshd_config modified" {
		t.Fatalf("message = %q, want generic sshd_config change", findings[0].Message)
	}
}

func TestCheckSSHDConfigAlertsOnEffectivePasswordAuthChange(t *testing.T) {
	cfgPath, st := testSSHDConfigStore(t, `PermitRootLogin without-password
PasswordAuthentication no
X11Forwarding no
`)

	if findings := CheckSSHDConfig(context.Background(), nil, st); len(findings) != 0 {
		t.Fatalf("initial baseline findings = %v, want none", findings)
	}

	writeSSHDConfig(t, cfgPath, `PermitRootLogin without-password
PasswordAuthentication yes
X11Forwarding no
`)

	findings := CheckSSHDConfig(context.Background(), nil, st)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want 1 critical alert", findings)
	}
	if findings[0].Message != "PasswordAuthentication changed to 'yes' in sshd_config" {
		t.Fatalf("message = %q, want PasswordAuthentication alert", findings[0].Message)
	}
}

func TestCheckSSHDConfigIgnoresMatchBlockOverrides(t *testing.T) {
	cfgPath, st := testSSHDConfigStore(t, `PermitRootLogin without-password
PasswordAuthentication no
X11Forwarding no
`)

	if findings := CheckSSHDConfig(context.Background(), nil, st); len(findings) != 0 {
		t.Fatalf("initial baseline findings = %v, want none", findings)
	}

	writeSSHDConfig(t, cfgPath, `PermitRootLogin without-password
PasswordAuthentication no
X11Forwarding no

Match User root
    PermitRootLogin yes
    PasswordAuthentication yes
    X11Forwarding yes
`)

	findings := CheckSSHDConfig(context.Background(), nil, st)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want 1 generic change alert", findings)
	}
	if findings[0].Message != "sshd_config modified" {
		t.Fatalf("message = %q, want generic sshd_config change", findings[0].Message)
	}
	for _, f := range findings {
		if strings.Contains(f.Message, "PasswordAuthentication changed") || strings.Contains(f.Message, "PermitRootLogin changed") {
			t.Fatalf("unexpected dangerous ssh finding from Match block: %v", findings)
		}
	}
}

func testSSHDConfigStore(t *testing.T, content string) (string, *state.Store) {
	t.Helper()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sshd_config")
	writeSSHDConfig(t, cfgPath, content)

	st, err := state.Open(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() {
		_ = st.Close()
	})

	oldPath := sshdConfigPath
	sshdConfigPath = cfgPath
	t.Cleanup(func() {
		sshdConfigPath = oldPath
	})

	return cfgPath, st
}

func writeSSHDConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("os.WriteFile(%s): %v", path, err)
	}
}
