package main

import (
	"net"
	"testing"

	"github.com/pidginhost/csm/internal/responsereplay"
)

func FuzzClassifyObservation(f *testing.F) {
	for _, seed := range [][3]string{
		{"CRITICAL", "AUTO-BLOCK: 203.0.113.4 blocked (expires in 30m0s)", "Reason: challenge timeout: x"},
		{"CRITICAL", "AUTO-BLOCK: 203.0.113.4 blocked (expires in 0s)", "Reason: CSM incident: x"},
		{"CRITICAL", "AUTO-BLOCK: 203.0.113.4 blocked (expires in -1h)", "Reason: central-intel (locally corroborated)"},
		{"WARNING", "AUTO-BLOCK [dry-run]: 203.0.113.4 would be blocked (expires in 1h0m0s)", "Reason: x"},
		{"CRITICAL", "AUTO-BLOCK-SUBNET: 203.0.113.0/24 blocked", ""},
		{"CRITICAL", "AUTO-BLOCK:  blocked (expires in 1h)", "Reason: CSM credential_spray: "},
		{"CRITICAL", "AUTO-BLOCK: alice.example.net blocked (expires in 1h)", "Reason: challenge timeout: x"},
		{"CRITICAL", "AUTO-BLOCK: 203.0.113.1:443 blocked (expires in 1h)", "Reason: CSM incident: x"},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}
	f.Fuzz(func(t *testing.T, severity, message, details string) {
		obs, kind := classifyObservation(responsereplay.Finding{Check: "auto_block", Severity: severity, Message: message, Details: details})
		// Only a positive lease on a single IP address is ever applied.
		if kind == observationNonScan && (obs.TTL <= 0 || net.ParseIP(obs.IP) == nil) {
			t.Fatalf("applied observation %+v", obs)
		}
		if kind == observationNone {
			t.Fatal("an auto_block row was not classified")
		}
	})
}

func FuzzParseSeverity(f *testing.F) {
	for _, seed := range []string{"WARNING", "HIGH", "CRITICAL", "UNKNOWN", "critical", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		sev, ok := parseSeverity(s)
		if ok && sev.String() != s {
			t.Fatalf("%q parsed as %v", s, sev)
		}
	})
}
