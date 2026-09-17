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
)

func TestOutboundSocketFindingsStampOwner(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	writePasswdFixture(t, root)
	cfg := &config.Config{C2Blocklist: []string{"203.0.113.9"}, BackdoorPorts: []int{4444}}
	for _, tc := range []struct {
		name, uid, owner string
	}{
		{"hosting", "1001", "alice"},
		{"other hosting", "1002", "bob"},
		{"root", "0", ""},
		{"service", "65534", ""},
		{"unknown", "4242", ""},
		{"malformed", "alice", ""},
		{"overflow", "4294968297", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := procTCPHeader + fmt.Sprintf("0: 010200C0:115C 097100CB:115C 01 00000000:00000000 00:00000000 00000000 %s 0 12345\n", tc.uid)
			withMockOS(t, &mockOS{readFile: func(path string) ([]byte, error) {
				if path == "/proc/net/tcp" {
					return []byte(data), nil
				}
				return nil, os.ErrNotExist
			}})
			findings := CheckOutboundConnections(context.Background(), cfg, nil)
			if len(findings) != 3 {
				t.Fatalf("got %d findings, want all three socket detections", len(findings))
			}
			for _, f := range findings {
				if f.TenantID != tc.owner || extractAccountFromFinding(f) != tc.owner {
					t.Errorf("%s: tenant %q, correlation owner %q, want %q", f.Check, f.TenantID, extractAccountFromFinding(f), tc.owner)
				}
				if f.SourceIP != "203.0.113.9" {
					t.Errorf("destination changed: %+v", f)
				}
			}
		})
	}
}

func TestOutboundSocketAccountsSurviveDeduplication(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	writePasswdFixture(t, root)
	var data strings.Builder
	data.WriteString(procTCPHeader)
	for _, uid := range []string{"1001", "1002", "1001"} {
		fmt.Fprintf(&data, "0: 010200C0:115C 097100CB:115C 01 00000000:00000000 00:00000000 00000000 %s 0 12345\n", uid)
	}
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return []byte(data.String()), nil }})
	cfg := &config.Config{C2Blocklist: []string{"203.0.113.9"}, BackdoorPorts: []int{4444}}
	got := alert.Deduplicate(CheckOutboundConnections(context.Background(), cfg, nil))
	if len(got) != 6 {
		t.Fatalf("got %d deduplicated findings, want three checks for each of two accounts", len(got))
	}
	for _, check := range []string{"c2_connection", "backdoor_port", "backdoor_port_outbound"} {
		owners := ownersByCheck(got, check)
		if len(owners) != 2 || owners["alice"] != 1 || owners["bob"] != 1 {
			t.Errorf("%s owners = %v", check, owners)
		}
	}
	res := CorrelateFindings(append(got, critical("db_rogue_admin", "carol")))
	if len(res.Derived) != 1 || res.Derived[0].Check != "coordinated_attack" || len(res.Unattributed) != 0 {
		t.Fatalf("socket evidence did not complete cross-account correlation: %+v", res)
	}
}

func TestBadASNScanFindingsStampOwner(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	writePasswdFixture(t, root)
	cfg := cfgWithBadASN(true, []uint{64500}, nil)
	SetASNLookup(func(string) (uint, string) { return 64500, "Example network" })
	t.Cleanup(func() { SetASNLookup(nil) })
	for _, ipv6 := range []bool{false, true} {
		for _, tc := range []struct{ uid, owner string }{{"1001", "alice"}, {"1002", "bob"}, {"0", ""}, {"65534", ""}, {"4242", ""}} {
			t.Run(fmt.Sprintf("ipv6=%t/uid=%s", ipv6, tc.uid), func(t *testing.T) {
				local, remote := "010200C0:C350", "097100CB:01BB"
				if ipv6 {
					local, remote = "B80D0120000000000000000001000000:C350", "B80D0120000000000000000009000000:01BB"
				}
				data := fmt.Sprintf("0: %s %s 01 00000000:00000000 00:00000000 00000000 %s 0 12345\n", local, remote, tc.uid)
				got := scanProcNetTCP(cfg, []byte(data), ipv6)
				f, ok := findingForCheck(got, "bad_asn_outbound")
				if !ok || f.TenantID != tc.owner || extractAccountFromFinding(f) != tc.owner {
					t.Fatalf("findings %+v, want bad-ASN owner %q", got, tc.owner)
				}
			})
		}
	}
}

func TestBadASNScanAccountsSurviveDeduplication(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	writePasswdFixture(t, root)
	cfg := cfgWithBadASN(true, []uint{64500}, nil)
	SetASNLookup(func(string) (uint, string) { return 64500, "Example network" })
	t.Cleanup(func() { SetASNLookup(nil) })
	var data strings.Builder
	for _, uid := range []string{"1001", "1002", "1001"} {
		fmt.Fprintf(&data, "0: 010200C0:C350 097100CB:01BB 01 00000000:00000000 00:00000000 00000000 %s 0 12345\n", uid)
	}
	got := alert.Deduplicate(scanProcNetTCP(cfg, []byte(data.String()), false))
	owners := ownersByCheck(got, "bad_asn_outbound")
	if len(owners) != 2 || owners["alice"] != 1 || owners["bob"] != 1 {
		t.Fatalf("deduplicated bad-ASN owners = %v, want alice and bob", owners)
	}
}

func TestSocketUIDZeroNeverBecomesHostingOwner(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	withMockPasswd(t, "alice:x:0:0::"+filepath.Join(root, "alice")+":/bin/sh\n")
	f := alert.Finding{Check: "bad_asn_outbound", Message: "connection"}
	AttributeSocketOwner(&f, 0)
	if f.TenantID != "" || f.Message != "connection" {
		t.Fatalf("uid zero was attributed through a passwd alias: %+v", f)
	}
}
