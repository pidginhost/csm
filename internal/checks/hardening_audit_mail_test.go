package checks

import (
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

func withMockMTA(t *testing.T, kind platform.MTAKind) {
	t.Helper()
	old := detectMTA
	detectMTA = func() platform.MTAKind { return kind }
	t.Cleanup(func() { detectMTA = old })
}

func withMockCPanel(t *testing.T, cpanel bool) {
	t.Helper()
	old := isCPanelHost
	isCPanelHost = func() bool { return cpanel }
	t.Cleanup(func() { isCPanelHost = old })
}

func TestAuditMailSkipsEximChecksOnPostfixHost(t *testing.T) {
	withMockMTA(t, platform.MTAPostfix)
	withMockCmd(t, &mockCmd{
		run: func(name string, _ ...string) ([]byte, error) {
			if name == "exim" {
				t.Errorf("exim was executed on a postfix host")
			}
			return nil, os.ErrNotExist
		},
	})
	withMockOS(t, &mockOS{})

	for _, result := range auditMail() {
		if strings.HasPrefix(result.Name, "mail_exim") || result.Name == "mail_secure_auth" {
			t.Errorf("%s reported on a postfix host: %s / %s", result.Name, result.Status, result.Message)
		}
	}
}

func TestAuditMailKeepsMTAIndependentChecksOnPostfixHost(t *testing.T) {
	withMockMTA(t, platform.MTAPostfix)
	withMockCmd(t, &mockCmd{})
	withMockOS(t, &mockOS{})

	if _, ok := auditByName(auditMail(), "mail_root_forwarder"); !ok {
		t.Error("mail_root_forwarder should still run when Exim is absent")
	}
}

func TestAuditMailRunsEximChecksOnEximHost(t *testing.T) {
	withMockMTA(t, platform.MTAExim)
	withMockCPanel(t, false)
	withMockCmd(t, &mockCmd{
		run: func(name string, _ ...string) ([]byte, error) {
			if name == "exim" {
				return []byte("log_selector = +arguments\nopenssl_options = +no_sslv2\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockOS(t, &mockOS{})

	results := auditMail()
	for _, name := range []string{"mail_exim_logging", "mail_exim_tls"} {
		result, ok := auditByName(results, name)
		if !ok {
			t.Fatalf("%s missing on an Exim host", name)
		}
		if result.Status != "pass" {
			t.Errorf("%s = %s (%s), want pass", name, result.Status, result.Message)
		}
	}
	if _, ok := auditByName(results, "mail_secure_auth"); ok {
		t.Error("cPanel-only secure-auth setting reported on a non-cPanel Exim host")
	}
}

func TestAuditMailWarnsWhenEximIsUnqueryable(t *testing.T) {
	withMockMTA(t, platform.MTAExim)
	withMockCPanel(t, false)
	withMockCmd(t, &mockCmd{
		run: func(string, ...string) ([]byte, error) { return nil, os.ErrPermission },
	})
	withMockOS(t, &mockOS{})

	results := auditMail()
	for _, name := range []string{"mail_exim_logging", "mail_exim_tls"} {
		result, ok := auditByName(results, name)
		if !ok {
			t.Fatalf("%s missing", name)
		}
		if result.Status != "warn" {
			t.Errorf("%s = %s (%s), want warn", name, result.Status, result.Message)
		}
	}
}

func TestAuditMailChecksSecureAuthOnCPanelExim(t *testing.T) {
	withMockMTA(t, platform.MTAExim)
	withMockCPanel(t, true)
	withMockCmd(t, &mockCmd{})
	withMockOS(t, &mockOS{})

	result, ok := auditByName(auditMail(), "mail_secure_auth")
	if !ok {
		t.Fatal("mail_secure_auth missing on a cPanel Exim host")
	}
	if result.Status != "pass" {
		t.Errorf("mail_secure_auth = %s (%s), want pass for absent override", result.Status, result.Message)
	}
}

func TestAuditMailWarnsWhenCPanelSecureAuthCannotBeRead(t *testing.T) {
	withMockMTA(t, platform.MTAExim)
	withMockCPanel(t, true)
	withMockCmd(t, &mockCmd{})
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/etc/exim.conf.localopts" {
			return nil, os.ErrPermission
		}
		return nil, os.ErrNotExist
	}})

	result, ok := auditByName(auditMail(), "mail_secure_auth")
	if !ok {
		t.Fatal("mail_secure_auth missing")
	}
	if result.Status != "warn" {
		t.Errorf("mail_secure_auth = %s (%s), want warn", result.Status, result.Message)
	}
}

func TestAuditMailParsesCPanelSecureAuthAssignment(t *testing.T) {
	withMockMTA(t, platform.MTAExim)
	withMockCPanel(t, true)
	withMockCmd(t, &mockCmd{})
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/etc/exim.conf.localopts" {
			return []byte("require_secure_auth = 0\n"), nil
		}
		return nil, os.ErrNotExist
	}})

	result, _ := auditByName(auditMail(), "mail_secure_auth")
	if result.Status != "fail" {
		t.Errorf("mail_secure_auth = %s (%s), want fail", result.Status, result.Message)
	}
}

func TestAuditMailIgnoresCommentedCPanelSecureAuthAssignment(t *testing.T) {
	withMockMTA(t, platform.MTAExim)
	withMockCPanel(t, true)
	withMockCmd(t, &mockCmd{})
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/etc/exim.conf.localopts" {
			return []byte("# require_secure_auth=0\n"), nil
		}
		return nil, os.ErrNotExist
	}})

	result, _ := auditByName(auditMail(), "mail_secure_auth")
	if result.Status != "pass" {
		t.Errorf("mail_secure_auth = %s (%s), want pass", result.Status, result.Message)
	}
}

func TestAuditMailWarnsOnInvalidCPanelSecureAuthAssignment(t *testing.T) {
	withMockMTA(t, platform.MTAExim)
	withMockCPanel(t, true)
	withMockCmd(t, &mockCmd{})
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/etc/exim.conf.localopts" {
			return []byte("require_secure_auth=unexpected\n"), nil
		}
		return nil, os.ErrNotExist
	}})

	result, _ := auditByName(auditMail(), "mail_secure_auth")
	if result.Status != "warn" {
		t.Errorf("mail_secure_auth = %s (%s), want warn", result.Status, result.Message)
	}
}
