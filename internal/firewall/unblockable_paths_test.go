//go:build linux

package firewall

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The single-IP block path refuses non-routable addresses, but two other
// paths reach the blocked sets without going through it.
//
// subnetSafetyGuardLocked checks infra ranges and e.localAddrs, and
// localAddrGuardKey deliberately drops loopback from that set -- so a subnet
// containing loopback was not refused even though the single address was.
func TestSubnetSafetyGuardRefusesNonRoutableRanges(t *testing.T) {
	e := &Engine{}
	e.cfg = &FirewallConfig{}

	for _, cidr := range []string{
		"127.0.0.0/8",
		"127.0.0.1/32",
		"::1/128",
		"169.254.0.0/16",
		"fe80::/10",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("bad test CIDR %q: %v", cidr, err)
		}
		err = e.subnetSafetyGuardLocked(network)
		if err == nil {
			t.Errorf("subnetSafetyGuardLocked(%s) allowed a non-routable range", cidr)
			continue
		}
		if !strings.Contains(err.Error(), "refusing") {
			t.Errorf("subnetSafetyGuardLocked(%s) error = %q, want a refusal", cidr, err)
		}
	}
}

func TestSubnetSafetyGuardDistinguishesRangesFromHosts(t *testing.T) {
	e := &Engine{cfg: &FirewallConfig{}, statePath: t.TempDir()}
	e.localAddrsLookup = func() ([]string, error) { return nil, nil }
	for _, cidr := range []string{"0.0.0.0/8", "0.0.0.0/2", "198.51.100.0/24", "2001:db8::/32"} {
		if err := e.subnetSafetyGuardLocked(mustCIDR(t, cidr)); err != nil {
			t.Errorf("legitimate range %s refused: %v", cidr, err)
		}
	}
	for _, cidr := range []string{"0.0.0.0/32", "::/128", "126.0.0.0/7", "169.0.0.0/8", "fe00::/8", "ff00::/8", "ff12::/16", "ff10::/12"} {
		if err := e.subnetSafetyGuardLocked(mustCIDR(t, cidr)); err == nil {
			t.Errorf("range covering protected addresses %s accepted", cidr)
		}
	}
}

func TestRefusedPromotionPreservesTemporaryBlock(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	prior := FirewallState{Blocked: []BlockedEntry{{
		IP: "127.0.0.1", Reason: "temporary", Source: SourceSystem,
		BlockedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
	}}}
	if err := e.saveState(&prior); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(e.statePath, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if promoteErr := e.PromoteToPermanentBlock("::ffff:127.0.0.1", "permanent"); promoteErr == nil {
		t.Fatal("promotion accepted")
	}
	after, err := os.ReadFile(filepath.Join(e.statePath, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) || len(*captured) != 0 {
		t.Fatal("refused promotion changed persistent state or sent a kernel transaction")
	}
}

// A routable range must still be blockable, or subnet blocking stops working.
func TestSubnetSafetyGuardAllowsRoutableRange(t *testing.T) {
	e := &Engine{}
	e.cfg = &FirewallConfig{}

	_, network, err := net.ParseCIDR("198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.subnetSafetyGuardLocked(network); err != nil {
		t.Errorf("subnetSafetyGuardLocked refused a routable range: %v", err)
	}
}

// PromoteToPermanentBlock deliberately bypasses the ordinary block path,
// because that path skips an already-blocked IP. It therefore also bypassed
// the address guard, so an entry that reached the set before the guard
// existed could still be promoted to permanent.
func TestPromoteToPermanentBlockRefusesNonRoutable(t *testing.T) {
	e := &Engine{}
	e.cfg = &FirewallConfig{}

	for _, ip := range []string{"127.0.0.1", "::1", "169.254.1.1"} {
		err := e.PromoteToPermanentBlock(ip, "test")
		if err == nil {
			t.Errorf("PromoteToPermanentBlock(%q) returned no error; a non-routable address was promotable", ip)
			continue
		}
		if !strings.Contains(err.Error(), "refusing") {
			t.Errorf("PromoteToPermanentBlock(%q) error = %q, want a refusal", ip, err)
		}
	}
}
