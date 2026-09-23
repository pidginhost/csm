package main

import (
	"fmt"
	"io"
	"testing"
)

// The IPv4 map has a 17-bit range, so distinct addresses can share a
// pseudonym. The anonymizer counts both sides so a bundle can say how much
// merging it did.
func TestAddressCountsExposePseudonymCollisions(t *testing.T) {
	a := NewAnonymizer(testSalt())
	pseudonyms := map[string]bool{}
	raw := 0
	for _, prefix := range []string{"192.0.2.", "198.51.100.", "203.0.113."} {
		for i := range 256 {
			pseudonyms[a.IPv4(fmt.Sprintf("%s%d", prefix, i))] = true
			raw++
		}
	}
	// Mapping the same address again is not a new address.
	a.IPv4("192.0.2.1")
	a.IPv6("2001:db8::1")
	a.IPv6("2001:DB8:0::1")
	a.IPv6("::ffff:192.0.2.1")
	got := a.AddressCounts()
	want := addressCounts{IPv4Addresses: raw, IPv4Pseudonyms: len(pseudonyms), IPv6Addresses: 1, IPv6Pseudonyms: 1}
	if got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}
	if got.IPv4Pseudonyms >= got.IPv4Addresses {
		t.Fatalf("768 addresses in a 17-bit range produced no collision under the test salt: %+v", got)
	}
}

func TestManifestCarriesAddressCounts(t *testing.T) {
	f := newJoinFixture(t)
	if err := testRun().execute(f.args(), io.Discard); err != nil {
		t.Fatal(err)
	}
	manifest, _ := readManifest(t, f.manifest)
	addresses, ok := manifest["addresses"].(map[string]any)
	if !ok {
		t.Fatalf("manifest has no address counts: %v", manifest)
	}
	// The fixture names 203.0.113.9 and 203.0.113.10 in findings, actions
	// and firewall rows; nothing IPv6.
	for key, want := range map[string]float64{"ipv4_addresses": 2, "ipv4_pseudonyms": 2, "ipv6_addresses": 0, "ipv6_pseudonyms": 0} {
		if addresses[key] != want {
			t.Errorf("%s = %v, want %v", key, addresses[key], want)
		}
	}
}
