package daemon

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func TestBadASNEventAccountsSurviveWithoutProcessContext(t *testing.T) {
	passwd := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(passwd, []byte("alice:x:1001:1001::/home/alice:/bin/sh\nbob:x:1002:1002::/home/bob:/bin/sh\nnobody:x:65534:65534::/var/lib/nobody:/bin/false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checks.SwapUIDCacheForTest(passwd))
	t.Cleanup(checks.SetHostingAccountLookupForTest(func(name string) string {
		if name == "alice" || name == "bob" {
			return name
		}
		return ""
	}))
	checks.SetASNLookup(func(string) (uint, string) { return 64500, "Example network" })
	t.Cleanup(func() { checks.SetASNLookup(nil) })
	cfg := &config.Config{}
	cfg.Detection.BadASNOutbound.Enabled = true
	cfg.Detection.BadASNOutbound.BlockedASNs = []uint{64500}
	var findings []alert.Finding
	for _, tc := range []struct {
		uid   uint32
		owner string
	}{{1001, "alice"}, {1002, "bob"}, {1001, "alice"}, {65534, ""}, {4242, ""}} {
		ev := ConnectionEvent{UID: tc.uid, Family: 2, DstPort: 443, DstIP: net.ParseIP("203.0.113.9").To4()}
		got := evaluateConnectionEvent(cfg, platform.MTAIdents{}, ev, checks.LookupUser(tc.uid))
		if len(got) != 1 || got[0].Check != "bad_asn_outbound" || got[0].TenantID != tc.owner {
			t.Fatalf("uid %d findings %+v, want bad-ASN owner %q without process enrichment", tc.uid, got, tc.owner)
		}
		findings = append(findings, got...)
	}
	got := alert.Deduplicate(findings)
	owners := map[string]int{}
	for _, f := range got {
		owners[f.TenantID]++
	}
	if owners["alice"] != 1 || owners["bob"] != 1 || owners[""] == 0 {
		t.Fatalf("deduplicated owners = %v", owners)
	}
}
