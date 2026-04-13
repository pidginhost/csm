package checks

import (
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// --- checkDpkgVerify with mock command --------------------------------

func TestCheckDpkgVerifyModified(t *testing.T) {
	withMockCmd(t, &mockCmd{
		lookPath: func(name string) (string, error) {
			if name == "dpkg" {
				return "/usr/bin/dpkg", nil
			}
			return "", os.ErrNotExist
		},
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			return []byte("??5?????? /usr/sbin/sshd\n"), nil
		},
	})

	findings := checkDpkgVerify([]string{"openssh-server"})
	_ = findings
}

// --- scanEximMessage with mock header --------------------------------

func TestScanEximMessageWithMock(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte("From: alice@example.com\nSubject: Test\nTo: bob@example.com\n\nBody content here.\n"), nil
		},
	})

	cfg := &config.Config{}
	result := scanEximMessage("ABC123-DEF456-GH", "alice@example.com", cfg)
	_ = result
}

// --- extractEmailHeader with raw header data -------------------------

func TestExtractEmailHeader(t *testing.T) {
	data := "From: alice@example.com\r\nSubject: Test Email\r\nTo: bob@example.com\r\n\r\nBody.\r\n"
	got := extractEmailHeader(data, "Subject")
	if got != "Test Email" {
		t.Errorf("got %q, want Test Email", got)
	}
}

func TestExtractEmailHeaderMissing(t *testing.T) {
	data := "From: alice@example.com\r\n\r\nBody.\r\n"
	if got := extractEmailHeader(data, "X-Custom"); got != "" {
		t.Errorf("missing header should return empty, got %q", got)
	}
}

// --- fixQuarantineSpoolMessage with mock exim -------------------------

func TestFixQuarantineSpoolMessageNoID(t *testing.T) {
	result := fixQuarantineSpoolMessage("no message id here")
	if result.Success {
		t.Error("no message ID should not succeed")
	}
}

// --- CleanDatabaseSpam with no mysql ---------------------------------

func TestCleanDatabaseSpamNoMySQL(t *testing.T) {
	withMockCmd(t, &mockCmd{})
	withMockOS(t, &mockOS{})
	findings := CleanDatabaseSpam("alice")
	if len(findings) != 0 {
		t.Errorf("no mysql should produce 0, got %d", len(findings))
	}
}

// --- SetOS and SetCmdRunner exercise ---------------------------------

func TestSetOSAndRestore(t *testing.T) {
	old := osFS
	SetOS(&mockOS{})
	if osFS == old {
		t.Error("SetOS should change osFS")
	}
	SetOS(old)
}

func TestSetCmdRunnerAndRestore(t *testing.T) {
	old := cmdExec
	SetCmdRunner(&mockCmd{})
	if cmdExec == old {
		t.Error("SetCmdRunner should change cmdExec")
	}
	SetCmdRunner(old)
}
