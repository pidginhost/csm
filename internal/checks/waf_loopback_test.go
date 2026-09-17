package checks

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/netutil"
)

// Panel proxies attribute their requests to the host. Those denial counts
// must not tell the operator to block the server itself.
func TestWAFAttackBlockedSkipsLocalAddresses(t *testing.T) {
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	}))

	for _, ip := range []string{"127.0.0.1", "::1", "203.0.113.10"} {
		if wafAttackerIsReportable(ip) {
			t.Errorf("wafAttackerIsReportable(%q) = true; the host would be told to block itself", ip)
		}
	}
	for _, ip := range []string{"198.51.100.7", "2001:db8::99"} {
		if !wafAttackerIsReportable(ip) {
			t.Errorf("wafAttackerIsReportable(%q) = false; a real attacker was dropped", ip)
		}
	}
}

// A lookup failure must not silence real attackers.
func TestWAFAttackBlockedReportsWhenHostLookupFails(t *testing.T) {
	lookups := 0
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		lookups++
		return nil, net.UnknownNetworkError("boom")
	}))

	for _, ip := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::"} {
		if wafAttackerIsReportable(ip) {
			t.Errorf("local address %s reported when the host lookup failed", ip)
		}
	}
	if lookups != 0 {
		t.Fatalf("local-only checks performed %d lookups, want zero", lookups)
	}
	for _, ip := range []string{"198.51.100.7", "2001:db8::99"} {
		if !wafAttackerIsReportable(ip) {
			t.Errorf("lookup failure suppressed remote attacker %s", ip)
		}
	}
	if lookups != 2 {
		t.Errorf("remote checks performed %d lookups, want two failed lookups", lookups)
	}
}

// The guidance text must not survive for an address the operator cannot act on.
func TestWAFFindingAdviceOnlyForRemoteAttackers(t *testing.T) {
	for _, tc := range []struct {
		ip     string
		advise bool
	}{
		{"198.51.100.7", true},
		{"2001:db8::99", true},
		{"169.254.1.1", false},
		{"::ffff:169.254.1.1", false},
		{"fe80::1", false},
		{"224.0.0.1", false},
		{"::ffff:224.0.0.1", false},
		{"ff02::1", false},
		{"ff12::1", false},
		{"224.0.1.1", true},
		{"ff03::1", true},
	} {
		t.Run(tc.ip, func(t *testing.T) {
			t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
				return nil, net.UnknownNetworkError("boom")
			}))
			var log strings.Builder
			for i := 0; i < 20; i++ {
				log.WriteString(serialTransaction(fmt.Sprintf("denial%d", i), tc.ip, 403))
			}
			setupSerialAuditLog(t, log.String())
			findings := CheckModSecAuditLog(context.Background(), &config.Config{}, nil)
			if len(findings) != 1 {
				t.Fatalf("findings = %+v, want one attacker even if CSM cannot block it", findings)
			}
			f := findings[0]
			if f.SourceIP != net.ParseIP(tc.ip).String() || f.Check != "waf_attack_blocked" || f.Severity != alert.High {
				t.Fatalf("unexpected attacker finding: %+v", f)
			}
			if !strings.Contains(f.Details, "20 times") {
				t.Errorf("missing denial count: %q", f.Details)
			}
			if got := strings.Contains(f.Details, "Consider permanent block"); got != tc.advise {
				t.Errorf("block advice = %v, want %v: %q", got, tc.advise, f.Details)
			}
			if !tc.advise && !strings.Contains(f.Details, "Review the source of this link-local traffic") {
				t.Errorf("missing link-local guidance: %q", f.Details)
			}
		})
	}
}

func TestCheckModSecAuditLogSuppressesHostFindings(t *testing.T) {
	for _, lookupFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("lookupFails=%v", lookupFails), func(t *testing.T) {
			t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
				if lookupFails {
					return nil, net.UnknownNetworkError("boom")
				}
				return []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("2001:db8::10")}, nil
			}))
			for _, ip := range []string{"127.0.0.1", "::ffff:127.0.0.53", "::1", "0.0.0.0", "::", "203.0.113.10", "2001:db8::10"} {
				t.Run(ip, func(t *testing.T) {
					var log strings.Builder
					for i := 0; i < 20; i++ {
						log.WriteString(serialTransaction(fmt.Sprintf("local%d", i), ip, 403))
					}
					setupSerialAuditLog(t, log.String())
					findings := CheckModSecAuditLog(context.Background(), &config.Config{}, nil)
					want := 0
					if lookupFails && (ip == "203.0.113.10" || ip == "2001:db8::10") {
						want = 1
					}
					if len(findings) != want {
						t.Errorf("findings = %+v, want %d", findings, want)
					}
				})
			}
		})
	}
}
