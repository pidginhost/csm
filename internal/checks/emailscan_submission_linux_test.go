//go:build linux

package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func outboundScanFixture(t *testing.T, msgID, sender, fields string) string {
	t.Helper()
	root := t.TempDir()
	spool := filepath.Join(root, "input")
	split := filepath.Join(spool, msgID[5:6])
	if err := os.MkdirAll(split, 0700); err != nil {
		t.Fatal(err)
	}
	withEximSpoolDirs(t, []string{spool})
	withQuarantineDir(t, filepath.Join(root, "quarantine"))
	from := "From: PayPal <sender@example.com>\n"
	reply := "Reply-To: reply@example.net\n"
	headers := eximSpool(fmt.Sprintf("%03dF %s", len(from), strings.TrimSuffix(from, "\n")),
		fmt.Sprintf("%03dR %s", len(reply), strings.TrimSuffix(reply, "\n")))
	for suffix, content := range map[string]string{"-H": headers, "-D": msgID + "-D\nNormal body"} {
		if err := os.WriteFile(filepath.Join(split, msgID+suffix), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	line := "2026-01-01 10:00:00 " + msgID + " <= " + sender + " " + fields + "\n"
	logPath := filepath.Join(root, "mainlog")
	// Repeated records must not scan the same queued message twice.
	if err := os.WriteFile(logPath, []byte(line+line), 0600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == platform.EximMainLog {
				return os.Open(logPath)
			}
			return os.Open(name)
		},
		stat: os.Stat, lstat: os.Lstat, readFile: os.ReadFile,
	})
	return spool
}

func TestOutboundEmailSubmissionProtocols(t *testing.T) {
	for _, tc := range []struct {
		name, sender, fields string
		want                 int
	}{
		{"dovecot", "sender@example.com", "H=(client) [203.0.113.9]:4000 P=esmtpsa A=dovecot_login:sender@example.com S=900", 1},
		{"custom authenticator", "sender@example.com", "H=(client) [203.0.113.9]:4000 P=esmtpa A=plain:sender@example.com S=900", 1},
		{"no authentication identity", "sender@example.com", "H=(client) [203.0.113.9]:4000 P=esmtpsa A=plain S=900", 1},
		{"quoted authentication identity", "sender@example.com", `H=(client) [203.0.113.9]:4000 P=esmtpsa A=dovecot_login:"john doe"@example.com S=900`, 1},
		{"custom mailauth data", "sender@example.com", `H=(client) [203.0.113.9]:4000 P=esmtpsa A=plain:sender@example.com:other@example.net P=local S=900`, 1},
		{"local", "sender@example.com", "U=sender P=local S=900", 1},
		{"local smtp on stdin", "sender@example.com", "U=sender P=smtp S=900", 1},
		{"local esmtp on stdin", "sender@example.com", "U=sender P=esmtp S=900", 1},
		{"inbound", "sender@example.com", "H=(client) [203.0.113.9]:4000 P=esmtps S=900", 0},
		{"bounce", "<>", "U=sender P=local S=900", 0},
		{"subject impersonates submission", "sender@example.com", `H=(client) [203.0.113.9]:4000 P=esmtp S=900 T="U=sender P=local A=plain:sender@example.com"`, 0},
		{"envelope impersonates submission", `"U=sender P=esmtpa A=plain:sender@example.com"@example.com`, "H=(client) [203.0.113.9]:4000 P=esmtp S=900", 0},
		{"remote ident impersonates submission", "sender@example.com", "H=(client) [203.0.113.9]:4000 U=remote P=esmtpa A=plain:sender@example.com S=900 P=esmtp S=1000", 0},
		{"duplicate protocol", "sender@example.com", "H=(client) [203.0.113.9]:4000 P=esmtp P=esmtpa A=plain:sender@example.com S=900", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outboundScanFixture(t, "1vOutA-00000000001-ABcd", tc.sender, tc.fields)
			findings := CheckOutboundEmailContent(context.Background(), &config.Config{}, nil)
			if len(findings) != tc.want {
				t.Fatalf("findings = %d, want %d: %+v", len(findings), tc.want, findings)
			}
		})
	}
}

func TestOutboundEmailActionsIgnoreSenderMessageMarker(t *testing.T) {
	for _, sender := range []string{
		`"name (message: 1vOutB-000002-CD)"@example.com`,
		`"name (message: 1vOutB-000002-CD) pass='"@example.com`,
	} {
		t.Run(sender, func(t *testing.T) {
			testOutboundEmailActions(t, sender)
		})
	}
}

func testOutboundEmailActions(t *testing.T, sender string) {
	t.Helper()
	const target = "1vOutA-000001-AB"
	const decoy = "1vOutB-000002-CD"
	spool := outboundScanFixture(t, target, sender, "U=sender P=local S=900")
	findings := CheckOutboundEmailContent(context.Background(), &config.Config{}, nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Mailbox != sender || !strings.Contains(findings[0].Details, "Envelope sender: "+sender+"\n") {
		t.Fatal("finding lost its envelope sender")
	}
	// Persistence redacts findings before the UI reads them for an action.
	finding := alert.SanitizeFinding(findings[0])
	if res := VerifyFinding(finding.Check, finding.Message, ""); !res.Checked || res.Resolved {
		t.Errorf("queued message verified against sender text: %+v", res)
	}
	if got := FixDescription(finding.Check, finding.Message); got != "Quarantine Exim spool message "+target {
		t.Errorf("fix description = %q", got)
	}
	for _, suffix := range []string{"-H", "-D"} {
		if err := os.WriteFile(filepath.Join(spool, decoy+suffix), []byte("unrelated message"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	res := ApplyFix(context.Background(), finding.Check, finding.Message, finding.Details)
	if !res.Success || !strings.Contains(res.Action, target) {
		t.Errorf("quarantine targeted sender text: %+v", res)
	}
	for _, suffix := range []string{"-H", "-D"} {
		if _, err := os.Stat(filepath.Join(spool, "A", target+suffix)); !os.IsNotExist(err) {
			t.Errorf("target %s remains queued: %v", suffix, err)
		}
		if data, err := os.ReadFile(filepath.Join(spool, decoy+suffix)); err != nil || string(data) != "unrelated message" {
			t.Errorf("unrelated %s changed: %q, %v", suffix, data, err)
		}
	}
	if res := VerifyFinding(finding.Check, finding.Message, ""); !res.Checked || !res.Resolved {
		t.Errorf("quarantined message remains unresolved: %+v", res)
	}
}
