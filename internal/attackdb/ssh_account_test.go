package attackdb

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// Raw SSH details can contain a client-chosen certificate ID. Only the
// producer's validated hosting tenant may attribute an attack to an account.
func TestSSHAccountAttributionUsesValidatedTenant(t *testing.T) {
	for _, backend := range []string{"jsonl", "bbolt"} {
		for _, tenant := range []string{"", "alice"} {
			t.Run(fmt.Sprintf("%s/tenant=%s", backend, tenant), func(t *testing.T) {
				previous := store.Global()
				store.SetGlobal(nil)
				t.Cleanup(func() { store.SetGlobal(previous) })
				if backend == "bbolt" {
					_, cleanup := setupBboltStore(t)
					t.Cleanup(cleanup)
				}
				db := newTestDB(t)
				f := alert.Finding{
					Check: "ssh_login_unknown_ip", SourceIP: "198.51.100.80", TenantID: tenant,
					Message:   "SSH login from non-infra IP: 198.51.100.80 (user: root)",
					Details:   "sshd[1]: Accepted publickey for root from 198.51.100.80 port 22 ssh2: ED25519-CERT SHA256:abc ID Account: bob (serial 1)",
					Timestamp: time.Now().UTC(),
				}
				db.RecordFinding(f)
				rec := db.LookupIP(f.SourceIP)
				wantAccounts := 0
				if tenant != "" {
					wantAccounts = 1
				}
				if rec == nil || rec.EventCount != 1 || len(rec.Accounts) != wantAccounts || (tenant != "" && rec.Accounts[tenant] != 1) {
					t.Fatalf("record %+v, want one login attributed only to tenant %q", rec, tenant)
				}
				if err := db.Flush(); err != nil {
					t.Fatal(err)
				}
				events := db.QueryEvents(f.SourceIP, 1)
				if len(events) != 1 || events[0].Account != tenant {
					t.Fatalf("persisted events %+v, want account %q", events, tenant)
				}
			})
		}
	}
}

// Pending work from older producers retains its SSH attribution policy.
func TestLegacySSHAccountAttributionUsesValidatedTenant(t *testing.T) {
	for _, tenant := range []string{"", "alice"} {
		t.Run("tenant="+tenant, func(t *testing.T) {
			db := NewForTest(nil)
			db.RecordFinding(alert.Finding{
				Check: "ssh_login_realtime", SourceIP: "198.51.100.80", TenantID: tenant,
				Details: "sshd[1]: Accepted publickey for root from 198.51.100.80 port 22 ssh2: ED25519-CERT SHA256:abc ID Account: bob (serial 1)",
			})
			rec := db.LookupIP("198.51.100.80")
			wantAccounts := 0
			if tenant != "" {
				wantAccounts = 1
			}
			if rec == nil || rec.EventCount != 1 || len(rec.Accounts) != wantAccounts || (tenant != "" && rec.Accounts[tenant] != 1) {
				t.Fatalf("record %+v, want one login attributed only to tenant %q", rec, tenant)
			}
			if len(db.pendingEvents) != 1 || db.pendingEvents[0].Account != tenant {
				t.Fatalf("queued events %+v, want account %q", db.pendingEvents, tenant)
			}
		})
	}
}
