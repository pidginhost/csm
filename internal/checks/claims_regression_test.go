package checks

import (
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/config"
)

func TestASNCrawlClaimsAllObservedVhosts(t *testing.T) {
	cfg := configWithASNCrawlDefaults(t)
	for _, tc := range []struct {
		name    string
		domains map[string]string
		claims  []admission.Claim
		owner   string
	}{
		{"same owner", map[string]string{"shop.example.com": "acct1", "www.example.com": "acct1"},
			[]admission.Claim{{Kind: admission.ClaimDomain, Value: "shop.example.com"}, {Kind: admission.ClaimDomain, Value: "www.example.com"}}, "acct:acct1#1"},
		{"conflicting owners", map[string]string{"shop.example.com": "acct1", "www.example.com": "acct2"},
			[]admission.Claim{{Kind: admission.ClaimDomain, Value: "shop.example.com"}, {Kind: admission.ClaimDomain, Value: "www.example.com"}}, "host"},
		{"no vhost identity", nil, nil, "host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := asnCrawlStatsWith(t, cfg, "acct1", 64500, "Example", 30, 600, 600, 600)
			for domain := range tc.domains {
				s.asnCrawl["acct1"].byASN[64500].domains[domain] = struct{}{}
			}
			out := s.emitASNCrawl(cfg)
			if len(out) != 1 {
				t.Fatalf("findings %+v, want one crawl", out)
			}
			if !slices.Equal(out[0].Claims, tc.claims) {
				t.Fatalf("claims %+v, want %+v", out[0].Claims, tc.claims)
			}
			claimsDeclared(t, ProducerDomlogScan, out[0])
			inv, err := admission.NewInventory(map[string]uint64{"acct1": 1, "acct2": 2}, tc.domains)
			if err != nil {
				t.Fatal(err)
			}
			if owner := inv.Resolve(out[0].Claims...); owner.Key() != tc.owner {
				t.Fatalf("owner %s, want %s", owner.Key(), tc.owner)
			}
		})
	}
}

func TestSSHOwnershipRequiresAuthenticatedLogIdentity(t *testing.T) {
	t.Cleanup(SetHostingAccountLookupForTest(func(name string) string {
		if name == "alice" {
			return name
		}
		return ""
	}))
	for _, line := range []string{
		"Oct  2 12:00:00 Accepted sshd[100]: Failed password for alice from 192.0.2.40 port 50000 ssh2",
		"Oct  2 12:00:00 host sshd[100]: Failed password for alice from 192.0.2.40 port 50000 ssh2 Accepted",
		"Oct  2 12:00:00 host other[100]: Accepted password for alice from 192.0.2.40 port 50000 ssh2",
		"Oct  2 12:00:00 host sshd[100]: error: Accepted password for alice from 192.0.2.40 port 50000 ssh2",
	} {
		f, _ := SSHAcceptedLoginFinding(line, &config.Config{})
		if f.TenantID != "" || len(f.Claims) != 0 {
			t.Errorf("unverified authentication acquired ownership: %+v", f)
		}
	}
	for _, prefix := range []string{
		"Oct  2 12:00:00 host sshd[100]: ",
		"2026-10-02T12:00:00Z host sshd[100]: ",
		"Oct  2 12:00:00 host sshd: ",
		"Oct  2 12:00:00 host sshd-session[100]: ",
	} {
		f, ok := SSHAcceptedLoginFinding(prefix+"Accepted publickey for alice from 192.0.2.40 port 50000 ssh2", &config.Config{})
		want := []admission.Claim{{Kind: admission.ClaimAccount, Value: "alice"}}
		if !ok || f.TenantID != "alice" || !slices.Equal(f.Claims, want) {
			t.Errorf("authenticated hosting account lost ownership: %+v (ok %v)", f, ok)
		}
	}
}
