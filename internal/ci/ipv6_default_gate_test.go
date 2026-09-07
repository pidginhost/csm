package ci

import (
	"os"
	"regexp"
	"testing"
)

// firewall.ipv6 defaults to false, and false means every IPv6 packet bypasses
// the firewall entirely: the engine inserts a blanket accept ahead of the
// blocked sets and every port rule, and the blocked-IP sets are IPv4-only, so
// a blocked attacker can simply reconnect over IPv6.
//
// The shipped config did not mention the key at all, so an operator reading
// their own firewall section had no way to know the choice existed or that
// they were on the unfiltered side of it. Ship it declared.
func TestShippedConfigDeclaresFirewallIPv6(t *testing.T) {
	for _, path := range []string{
		"../../build/packaging/csm.yaml.default",
		"../../configs/csm.yaml.production.example",
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		cfg := string(data)

		if !regexp.MustCompile(`(?m)^\s+ipv6:\s`).MatchString(cfg) {
			t.Errorf("%s does not declare firewall.ipv6; operators cannot see that IPv6 is unfiltered by default", path)
			continue
		}
		// Declared but off would ship the same silent bypass with extra words.
		if !regexp.MustCompile(`(?m)^\s+ipv6:\s+true`).MatchString(cfg) {
			t.Errorf("%s declares firewall.ipv6 but not as true; a dual-stack host would still accept all IPv6 unfiltered", path)
		}
		// An empty tcp6_in inherits tcp_in, which is what makes enabling it
		// safe by default. Ship the override keys visible alongside it.
		for _, key := range []string{"tcp6_in", "udp6_in"} {
			if !regexp.MustCompile(`(?m)^\s+` + key + `:`).MatchString(cfg) {
				t.Errorf("%s does not declare %s next to ipv6", path, key)
			}
		}
	}
}
