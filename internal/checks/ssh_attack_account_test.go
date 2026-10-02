package checks

import (
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/attackdb"
)

func TestSSHCertificateTextCannotSupplyAttackAccount(t *testing.T) {
	t.Cleanup(SetHostingAccountLookupForTest(func(name string) string {
		if name == "alice" {
			return name
		}
		return ""
	}))
	for _, user := range []string{"root", "daemon", "alice"} {
		t.Run(user, func(t *testing.T) {
			line := fmt.Sprintf("sshd[1]: Accepted publickey for %s from 198.51.100.80 port 22 ssh2: ED25519-CERT SHA256:abc ID Account: bob (serial 1)", user)
			f, ok := SSHAcceptedLoginFinding(line, nil)
			if !ok {
				t.Fatal("successful SSH login was not reported")
			}
			wantTenant := ""
			if user == "alice" {
				wantTenant = "alice"
				if len(f.Claims) != 1 || f.Claims[0] != (admission.Claim{Kind: admission.ClaimAccount, Value: "alice"}) {
					t.Fatalf("hosting login claims %+v, want alice", f.Claims)
				}
			} else if len(f.Claims) != 0 {
				t.Fatalf("non-hosting login claims %+v, want none", f.Claims)
			}
			if f.TenantID != wantTenant {
				t.Fatalf("tenant %q, want %q", f.TenantID, wantTenant)
			}
			db := attackdb.NewForTest(nil)
			db.RecordFinding(f)
			rec := db.LookupIP("198.51.100.80")
			wantAccounts := 0
			if wantTenant != "" {
				wantAccounts = 1
			}
			if rec == nil || rec.EventCount != 1 || len(rec.Accounts) != wantAccounts || (wantTenant != "" && rec.Accounts[wantTenant] != 1) {
				t.Fatalf("record %+v, want account %q only", rec, wantTenant)
			}
		})
	}
}
