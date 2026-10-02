package checks

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// claimsDeclared fails when a finding carries a claim kind its producer does
// not declare in the producer table: Mint would refuse that evidence.
func claimsDeclared(t *testing.T, id admission.ProducerID, f alert.Finding) {
	t.Helper()
	for _, p := range ProducerTable() {
		if p.Spec.ID != id {
			continue
		}
		for _, c := range f.Claims {
			if !slices.Contains(p.Spec.Claims, c.Kind) {
				t.Errorf("%s finding claims %+v, which %s does not declare", f.Check, c, id)
			}
		}
		return
	}
	t.Fatalf("no producer %s", id)
}

// An SSH login claims the account only when the login name is a hosting
// account; root and service users claim nothing.
func TestSSHLoginClaimsOnlyAHostingAccount(t *testing.T) {
	t.Cleanup(SetHostingAccountLookupForTest(func(name string) string {
		if name == "alice" {
			return "alice"
		}
		return ""
	}))
	for user, want := range map[string][]admission.Claim{
		"alice":  {{Kind: admission.ClaimAccount, Value: "alice"}},
		"root":   nil,
		"deploy": nil,
	} {
		line := "Oct  2 12:00:00 host sshd[100]: Accepted publickey for " + user + " from 192.0.2.40 port 50000 ssh2"
		f, ok := SSHAcceptedLoginFinding(line, &config.Config{})
		if !ok {
			t.Fatalf("%s: no finding", user)
		}
		if !reflect.DeepEqual(f.Claims, want) {
			t.Errorf("%s: claims %+v, want %+v", user, f.Claims, want)
		}
		claimsDeclared(t, ProducerSSHLog, f)
		claimsDeclared(t, ProducerSSHLoginScan, f)
	}
	failed := "Oct  2 12:00:00 host sshd[100]: Failed password for alice from 192.0.2.40 port 50000 ssh2"
	if f, ok := SSHAcceptedLoginFinding(failed, &config.Config{}); ok || len(f.Claims) != 0 {
		t.Fatalf("failed sshd name became a login/account claim: %+v", f)
	}
}

// A finding built from one vhost's log claims that vhost's domain; a source
// seen across vhosts claims none.
func TestDomlogFindingsClaimTheirVhost(t *testing.T) {
	now := time.Date(2026, 5, 20, 18, 5, 0, 0, time.FixedZone("EEST", 3*3600))
	cfg := &config.Config{}
	cfg.Thresholds.HTTPFloodThreshold = 50
	cfg.Thresholds.HTTPFloodWindowMin = 5
	for _, c := range []struct {
		domains []string
		want    []admission.Claim
	}{
		{[]string{"example.com"}, []admission.Claim{{Kind: admission.ClaimDomain, Value: "example.com"}}},
		{[]string{"example.com", "example.org"}, nil},
	} {
		stats := newDomlogStatsAt(now)
		rec, _ := parseAccessLogRecord(`192.0.2.60 - - [20/May/2026:18:00:00 +0300] "GET /a HTTP/1.1" 200 100 "-" "Mozilla/5.0"`)
		for i := 0; i < 75; i++ {
			rec.Domain = c.domains[i%len(c.domains)]
			stats.scan(rec, cfg, nopBotClassifier{})
		}
		got := stats.emit(cfg)
		if len(got) != 1 || got[0].Check != "http_request_flood" {
			t.Fatalf("emit = %+v", got)
		}
		if !reflect.DeepEqual(got[0].Claims, c.want) {
			t.Errorf("%v: claims %+v, want %+v", c.domains, got[0].Claims, c.want)
		}
		claimsDeclared(t, ProducerDomlogScan, got[0])
	}
}

// A crawl scoped to a hosting account claims it, and its single domain too.
func TestASNCrawlClaimsItsScope(t *testing.T) {
	cfg := configWithASNCrawlDefaults(t)
	s := asnCrawlStatsWith(t, cfg, "acct1", 64500, "Example", 30, 600, 600, 600)
	s.asnCrawl["acct1"].byASN[64500].domains["shop.example.com"] = struct{}{}
	out := s.emitASNCrawl(cfg)
	if len(out) != 1 {
		t.Fatalf("emit = %+v", out)
	}
	want := []admission.Claim{{Kind: admission.ClaimAccount, Value: "acct1"}, {Kind: admission.ClaimDomain, Value: "shop.example.com"}}
	if out[0].TenantID != "acct1" || out[0].Domain != "shop.example.com" || !reflect.DeepEqual(out[0].Claims, want) {
		t.Fatalf("finding %+v, want account and domain claims", out[0])
	}
	claimsDeclared(t, ProducerDomlogScan, out[0])
}

// The tenant of an SSH login is the hosting account it names, or none: root
// and service users are not tenants.
func TestSSHLoginTenantIsAHostingAccount(t *testing.T) {
	t.Cleanup(SetHostingAccountLookupForTest(func(name string) string {
		if name == "alice" {
			return "alice"
		}
		return ""
	}))
	for user, want := range map[string]string{"alice": "alice", "root": "", "deploy": "", "unknown": ""} {
		line := "Oct  2 12:00:00 host sshd[100]: Accepted password for " + user + " from 192.0.2.41 port 50000 ssh2"
		f, ok := SSHAcceptedLoginFinding(line, &config.Config{})
		if !ok || f.TenantID != want {
			t.Errorf("%s: tenant %q (ok %v), want %q", user, f.TenantID, ok, want)
		}
	}
}
