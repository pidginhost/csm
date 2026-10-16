package ipmap

import (
	"net/netip"
	"testing"
)

func TestJudge(t *testing.T) {
	for _, tc := range []struct {
		ok    bool
		score int
		want  Verdict
	}{
		{true, 150, SpamVerdict},
		{true, 149, NoVerdict},
		{true, 59, HamVerdict},
		{true, 60, NoVerdict},
		{true, -20, HamVerdict},
		{false, 200, NoVerdict},
	} {
		if got := Judge(tc.ok, tc.score, 0, 15, 6); got != tc.want {
			t.Errorf("Judge(%v, %d) = %v, want %v", tc.ok, tc.score, got, tc.want)
		}
	}
}

// A message rejected only because CSM's map listed its sender is not new
// evidence; the map would otherwise feed itself (spec 7.2).
func TestVerdictSubtractsTheMapWeight(t *testing.T) {
	if got := Judge(true, 170, Drop.Tenths(), 15, 6); got != NoVerdict {
		t.Fatalf("170 - 40 = 130 is between tag and reject, got %v", got)
	}
	if got := Judge(true, 190, Drop.Tenths(), 15, 6); got != SpamVerdict {
		t.Fatalf("190 - 40 = 150 reaches reject, got %v", got)
	}
	if got := Judge(true, 89, Spam.Tenths(), 15, 6); got != HamVerdict {
		t.Fatalf("89 - 30 = 59 is ham against tag 6.0, got %v", got)
	}
}

func TestRecordable(t *testing.T) {
	never := []netip.Addr{netip.MustParseAddr("203.0.113.60")}
	for ip, want := range map[string]bool{
		"203.0.113.61": true,
		"2001:db8::61": true,
		"192.0.2.255":  false, // the canary
		"10.0.0.1":     false,
		"127.0.0.1":    false,
		"169.254.0.1":  false,
		"203.0.113.60": false,
		"::1":          false,
	} {
		if got := Recordable(netip.MustParseAddr(ip), never); got != want {
			t.Errorf("Recordable(%s) = %v, want %v", ip, got, want)
		}
	}
	if Recordable(netip.Addr{}, nil) {
		t.Error("a marker without a sender is recordable")
	}
}
