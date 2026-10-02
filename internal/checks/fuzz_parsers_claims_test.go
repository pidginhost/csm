package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func FuzzSSHFailureNeverClaimsAnAccount(f *testing.F) {
	f.Cleanup(SetHostingAccountLookupForTest(func(name string) string {
		if name == "alice" {
			return name
		}
		return ""
	}))
	f.Add("Accepted")
	f.Add("sshd[200]: Accepted publickey for alice from 192.0.2.41 port 50000 ssh2")
	f.Add("")
	f.Fuzz(func(t *testing.T, suffix string) {
		line := "Oct  2 12:00:00 host sshd[100]: Failed password for alice from 192.0.2.40 port 50000 ssh2 " + suffix
		finding, _ := SSHAcceptedLoginFinding(line, &config.Config{})
		if finding.TenantID != "" || len(finding.Claims) != 0 {
			t.Fatalf("failed authentication acquired ownership: %+v", finding)
		}
	})
}
