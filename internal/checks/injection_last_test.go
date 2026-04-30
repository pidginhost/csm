package checks

import (
	"os"
	"strings"
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

// TestScanEximMessageWithMock exercises scanEximMessage against a minimal but
// valid cPanel-Exim -H spool blob (envelope preamble + blank-line separator +
// NNNX-prefixed RFC 5322 header lines). The result is intentionally
// discarded; this is a smoke test for the seam, not an indicator-shape
// assertion -- those live in TestScanEximMessage{ReplyToMismatch,...}.
func TestScanEximMessageWithMock(t *testing.T) {
	const spool = "ABC123-DEF456-GH-H\n" +
		"alice 1000 1000\n" +
		"<alice@example.com>\n" +
		"1700000000 0\n" +
		"-local\n" +
		"1\n" +
		"bob@example.com\n" +
		"\n" +
		"048F From: <alice@example.com>\n" +
		"037T To: bob@example.com\n" +
		"021  Subject: Test\n"

	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if strings.HasSuffix(name, "-H") {
				return fakeFileInfo{name: "msg-H"}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "-H") {
				return []byte(spool), nil
			}
			if strings.HasSuffix(name, "-D") {
				return []byte("Body content here."), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	result := scanEximMessage("ABC123-DEF456-GH", "alice@example.com", cfg)
	_ = result
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
