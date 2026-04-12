package checks

import (
	"os"
	"testing"
)

// --- checkUnnecessaryServices with mock systemctl ---------------------

func TestCheckUnnecessaryServicesActive(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "systemctl" && len(args) >= 2 && args[0] == "is-active" {
				return []byte("active\n"), nil
			}
			return nil, nil
		},
	})

	results := checkUnnecessaryServices()
	// Should check various services and report active ones
	if len(results) == 0 {
		t.Error("should produce results for service checks")
	}
}

// --- auditFirewall with nft and iptables output ----------------------

func TestAuditFirewallWithNftables(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "nft" {
				return []byte("table inet filter {\n  chain input {\n    type filter hook input priority 0;\n  }\n}\n"), nil
			}
			if name == "iptables" {
				return []byte("-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n"), nil
			}
			return nil, nil
		},
	})
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})

	results := auditFirewall()
	if len(results) == 0 {
		t.Error("auditFirewall should produce results")
	}
}

// --- auditSSH — exercise the maxauthtries and port checks -----------

func TestAuditSSHMaxAuthTries(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/etc/ssh/sshd_config" {
				tmp := t.TempDir() + "/sshd_config"
				content := "Port 22\nMaxAuthTries 10\nPermitRootLogin no\nPasswordAuthentication no\n"
				_ = os.WriteFile(tmp, []byte(content), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	results := auditSSH()
	if len(results) == 0 {
		t.Error("should produce SSH audit results")
	}
}

// --- auditPHP with mock php.ini and PHP version ----------------------

func TestAuditPHPWithVersions(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{"/opt/cpanel/ea-php82/root/etc/php.ini"}, nil
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/opt/cpanel/ea-php82/root/etc/php.ini" {
				return []byte("; PHP 8.2\ndisplay_errors = On\nallow_url_fopen = On\nexpose_php = On\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte("8.2.15"), nil
		},
	})

	results := auditPHP("cpanel")
	if len(results) == 0 {
		t.Error("should produce PHP audit results")
	}
	// Exercises the PHP config parsing + version detection paths.
	_ = results
}

// --- auditWebServer with mock config ---------------------------------

func TestAuditWebServerWithConfig(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte("ServerTokens Full\nServerSignature On\nTraceEnable On\n"), nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "httpd.conf", size: 100}, nil
		},
	})

	results := auditWebServer("cpanel")
	_ = results
}

// --- auditMail with exim config --------------------------------------

func TestAuditMailWithExim(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "exim" {
				return []byte("exim 4.96\n"), nil
			}
			return nil, nil
		},
	})
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})

	results := auditMail()
	_ = results
}
