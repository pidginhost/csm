package checks

import (
	"net"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/netutil"
)

// The control panel proxies its own requests over loopback, so ModSecurity
// denials attributed to 127.0.0.1 accumulate on any busy host. Reporting that
// as a "high-volume attacker" and advising a permanent block points the
// operator at their own machine:
//
//	[HIGH] waf_attack_blocked - WAF blocking high-volume attacker: 127.0.0.1
//	  IP 127.0.0.1 has been blocked 96 times. Consider permanent block via CSM.
//
// Acting on that advice is not harmless. The firewall's local-address guard
// deliberately excludes loopback, so the block is accepted rather than
// refused, and only the chain's leading "iifname lo accept" keeps traffic
// flowing while the address sits in the blocked set.
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
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return nil, net.UnknownNetworkError("boom")
	}))

	if !wafAttackerIsReportable("198.51.100.7") {
		t.Error("lookup failure suppressed a real attacker")
	}
	// Loopback is decided without the lookup, so it stays suppressed.
	if wafAttackerIsReportable("127.0.0.1") {
		t.Error("loopback reported when the host lookup failed")
	}
}

// The guidance text must not survive for an address the operator cannot act on.
func TestWAFFindingAdviceOnlyForRemoteAttackers(t *testing.T) {
	if !strings.Contains(wafBlockAdvice("198.51.100.7", 96), "permanent block") {
		t.Error("advice missing for a genuine remote attacker")
	}
}
