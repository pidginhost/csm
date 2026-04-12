package checks

import (
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// --- RunHardeningAudit with mocks ------------------------------------

func TestRunHardeningAuditWithMocks(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			// Provide a minimal sshd_config
			if name == "/etc/ssh/sshd_config" {
				tmp := t.TempDir() + "/sshd_config"
				_ = os.WriteFile(tmp, []byte("Port 22\nPermitRootLogin no\nPasswordAuthentication no\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/os-release" {
				return []byte("PRETTY_NAME=\"Ubuntu 24.04 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n"), nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
		lookPath: func(name string) (string, error) {
			return "", os.ErrNotExist
		},
	})

	cfg := &config.Config{StatePath: t.TempDir()}
	report := RunHardeningAudit(cfg)
	if report == nil {
		t.Fatal("report should not be nil")
	}
	if len(report.Results) == 0 {
		t.Error("should produce at least some audit results")
	}
}

// --- auditSSH with mock sshd_config ----------------------------------

func TestAuditSSHWithConfig(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/etc/ssh/sshd_config" {
				tmp := t.TempDir() + "/sshd_config"
				content := "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding yes\n"
				_ = os.WriteFile(tmp, []byte(content), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	results := auditSSH()
	if len(results) == 0 {
		t.Error("insecure sshd_config should produce results")
	}
	// Check that PermitRootLogin=yes produces a fail
	foundRootLogin := false
	for _, r := range results {
		if r.Name == "ssh_root_login" && r.Status == "fail" {
			foundRootLogin = true
		}
	}
	if !foundRootLogin {
		t.Error("PermitRootLogin=yes should produce ssh_root_login fail")
	}
}

func TestAuditSSHSecure(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/etc/ssh/sshd_config" {
				tmp := t.TempDir() + "/sshd_config"
				content := "Port 2222\nPermitRootLogin no\nPasswordAuthentication no\nX11Forwarding no\nMaxAuthTries 3\n"
				_ = os.WriteFile(tmp, []byte(content), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	results := auditSSH()
	for _, r := range results {
		if r.Status == "fail" && r.Name != "ssh_port" {
			t.Errorf("secure config should not fail on %s: %s", r.Name, r.Message)
		}
	}
}

// --- auditOS ---------------------------------------------------------

func TestAuditOSWithMocks(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/os-release" {
				return []byte("PRETTY_NAME=\"Ubuntu 24.04 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})

	results := auditOS()
	if len(results) == 0 {
		t.Error("auditOS should produce results")
	}
}

// --- auditFirewall ---------------------------------------------------

func TestAuditFirewallWithMocks(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})

	results := auditFirewall()
	if len(results) == 0 {
		t.Error("auditFirewall should produce results")
	}
}

// --- auditPHP --------------------------------------------------------

func TestAuditPHPWithMocks(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})
	withMockCmd(t, &mockCmd{})

	results := auditPHP("standalone")
	_ = results
}

// --- auditWebServer --------------------------------------------------

func TestAuditWebServerWithMocks(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})

	results := auditWebServer("standalone")
	_ = results
}

// --- auditMail -------------------------------------------------------

func TestAuditMailWithMocks(t *testing.T) {
	withMockCmd(t, &mockCmd{})
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})

	results := auditMail()
	_ = results
}
