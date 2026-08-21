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

	for _, r := range auditMail() {
		if strings.HasPrefix(r.Name, "mail_exim") || r.Name == "mail_secure_auth" {
			t.Errorf("%s reported on a postfix host: %s / %s", r.Name, r.Status, r.Message)
		}
	}
}

func TestAuditMailKeepsMTAIndependentChecksOnPostfixHost(t *testing.T) {
	withMockMTA(t, platform.MTAPostfix)
	withMockCmd(t, &mockCmd{})
	withMockOS(t, &mockOS{})

	if _, ok := auditByName(auditMail(), "mail_root_forwarder"); !ok {
		t.Error("mail_root_forwarder should still run when exim is absent")
	}
}

func TestAuditMailRunsEximChecksOnEximHost(t *testing.T) {
	withMockMTA(t, platform.MTAExim)
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
	r, ok := auditByName(results, "mail_exim_logging")
	if !ok {
		t.Fatal("mail_exim_logging missing on an exim host")
	}
	if r.Status != "pass" {
		t.Errorf("mail_exim_logging = %s (%s), want pass", r.Status, r.Message)
	}
	if _, ok := auditByName(results, "mail_secure_auth"); !ok {
		t.Error("mail_secure_auth missing on an exim host")
	}
}

func TestAuditMailWarnsWhenEximInstalledButUnqueryable(t *testing.T) {
	withMockMTA(t, platform.MTAExim)
	withMockCmd(t, &mockCmd{
		run: func(string, ...string) ([]byte, error) { return nil, os.ErrPermission },
	})
	withMockOS(t, &mockOS{})

	r, ok := auditByName(auditMail(), "mail_exim_logging")
	if !ok {
		t.Fatal("mail_exim_logging missing")
	}
	if r.Status != "warn" {
		t.Errorf("mail_exim_logging = %s (%s), want warn", r.Status, r.Message)
	}
}
