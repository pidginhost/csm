package firewall

import "testing"

func TestLiveBlockedSnapshotContains(t *testing.T) {
	snap := LiveBlockedSnapshot{
		V4:    map[string]struct{}{"203.0.113.7": {}},
		V6:    map[string]struct{}{"2001:db8::1": {}},
		HasV4: true,
		HasV6: true,
	}

	tests := []struct {
		name    string
		ip      string
		blocked bool
		known   bool
	}{
		{name: "v4 present", ip: "203.0.113.7", blocked: true, known: true},
		{name: "v4 absent", ip: "203.0.113.8", blocked: false, known: true},
		{name: "v6 present", ip: "2001:db8::1", blocked: true, known: true},
		{name: "v6 absent", ip: "2001:db8::2", blocked: false, known: true},
		// A dual-stack listener hands us the v4-mapped form; it must resolve
		// against the v4 set, matching how the block path keys its elements.
		{name: "v4-mapped v6 present", ip: "::ffff:203.0.113.7", blocked: true, known: true},
		// Mirrors IsBlockedLive, which reports malformed input as absent.
		{name: "malformed", ip: "not-an-ip", blocked: false, known: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blocked, known := snap.Contains(tc.ip)
			if blocked != tc.blocked || known != tc.known {
				t.Errorf("Contains(%q) = (%v, %v), want (%v, %v)", tc.ip, blocked, known, tc.blocked, tc.known)
			}
		})
	}
}

// A family the snapshot did not cover must report known=false so callers keep
// their cached answer. Reporting "absent" would prune every tracked v6 block
// on a host running with firewall.ipv6 disabled.
func TestLiveBlockedSnapshotUncoveredFamilyIsUnknown(t *testing.T) {
	v4Only := LiveBlockedSnapshot{
		V4:    map[string]struct{}{"203.0.113.7": {}},
		HasV4: true,
	}
	if blocked, known := v4Only.Contains("2001:db8::1"); blocked || known {
		t.Errorf("v6 lookup on a v4-only snapshot = (%v, %v), want (false, false)", blocked, known)
	}
	if blocked, known := v4Only.Contains("203.0.113.7"); !blocked || !known {
		t.Errorf("v4 lookup on a v4-only snapshot = (%v, %v), want (true, true)", blocked, known)
	}

	var empty LiveBlockedSnapshot
	if blocked, known := empty.Contains("203.0.113.7"); blocked || known {
		t.Errorf("zero-value snapshot = (%v, %v), want (false, false)", blocked, known)
	}
}
