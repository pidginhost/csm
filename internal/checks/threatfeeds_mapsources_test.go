package checks

import (
	"net"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestThreatDBMapSources(t *testing.T) {
	_, drop, _ := net.ParseCIDR("198.51.100.0/24")
	_, drop6, _ := net.ParseCIDR("2001:db8::/32")
	db := &ThreatDB{
		badIPs: map[string]string{
			"203.0.113.1": "permanent-blocklist",
			"203.0.113.2": "auto-block",
			"203.0.113.3": "blocklist-de",
			"203.0.113.5": "operator",
			"203.0.113.6": "auto-block",
		},
		badIPExpiry: map[string]time.Time{
			"203.0.113.2": time.Now().Add(time.Hour),
			"203.0.113.6": time.Now().Add(-time.Hour),
		},
		feedIPs: map[string]map[string]struct{}{
			"blocklist-de": {"203.0.113.3": {}, "203.0.113.1": {}},
			"cins-army":    {"203.0.113.4": {}, "203.0.113.3": {}},
		},
		feedNets:        map[string][]*net.IPNet{"spamhaus-drop": {drop6, drop}},
		whitelist:       map[string]bool{"192.0.2.10": true},
		configWhitelist: map[string]bool{"192.0.2.11": true, "192.0.2.10": true},
		whitelistMeta:   map[string]*whitelistEntry{},
	}
	got := db.MapSources()
	want := ThreatMapSources{
		Permanent: []string{"203.0.113.1", "203.0.113.5"},
		FeedIPs:   map[string][]string{"blocklist-de": {"203.0.113.1", "203.0.113.3"}, "cins-army": {"203.0.113.3", "203.0.113.4"}},
		FeedNets:  map[string][]string{"spamhaus-drop": {"198.51.100.0/24", "2001:db8::/32"}},
		Whitelist: []string{"192.0.2.10", "192.0.2.11"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MapSources = %+v\nwant %+v", got, want)
	}
	got.Permanent[0] = "192.0.2.99"
	got.FeedIPs["blocklist-de"][0] = "192.0.2.99"
	got.FeedNets["spamhaus-drop"][0] = "192.0.2.0/24"
	got.Whitelist[0] = "192.0.2.99"
	delete(got.FeedIPs, "cins-army")
	if next := db.MapSources(); !reflect.DeepEqual(next, want) {
		t.Fatalf("mutating a snapshot changed the DB: %+v\nwant %+v", next, want)
	}
}

func TestThreatDBMapSourcesWhitelistExpiry(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name       string
		entry      *whitelistEntry
		configured bool
		want       bool
	}{
		{name: "legacy permanent", want: true},
		{name: "permanent", entry: &whitelistEntry{}, want: true},
		{name: "live temporary", entry: &whitelistEntry{ExpiresAt: now.Add(time.Hour)}, want: true},
		{name: "expired temporary", entry: &whitelistEntry{ExpiresAt: now.Add(-time.Hour)}},
		{name: "expired but configured", entry: &whitelistEntry{ExpiresAt: now.Add(-time.Hour)}, configured: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const ip = "192.0.2.10"
			db := &ThreatDB{
				whitelist:       map[string]bool{ip: true},
				whitelistMeta:   map[string]*whitelistEntry{ip: tc.entry},
				configWhitelist: make(map[string]bool),
			}
			if tc.configured {
				db.SetConfigWhitelist([]string{ip})
			}
			var want []string
			if tc.want {
				want = []string{ip}
			}
			if got := db.MapSources().Whitelist; !slices.Equal(got, want) {
				t.Fatalf("Whitelist = %v, want %v", got, want)
			}
			if !db.whitelist[ip] || db.whitelistMeta[ip] != tc.entry {
				t.Fatal("snapshot pruned the underlying whitelist")
			}
			if tc.configured {
				db.SetConfigWhitelist(nil)
				if got := db.MapSources().Whitelist; len(got) != 0 {
					t.Fatalf("Whitelist after config removal = %v, want empty", got)
				}
			}
		})
	}
}

// The recorder skips exactly the addresses MapSources keeps out of the map:
// operator and config entries, and temporary entries until they expire.
func TestThreatDBIsWhitelisted(t *testing.T) {
	now := time.Now()
	db := &ThreatDB{
		whitelist: map[string]bool{"192.0.2.10": true, "192.0.2.12": true, "192.0.2.13": true},
		whitelistMeta: map[string]*whitelistEntry{
			"192.0.2.12": {ExpiresAt: now.Add(time.Hour)},
			"192.0.2.13": {ExpiresAt: now.Add(-time.Hour)},
		},
		configWhitelist: map[string]bool{"192.0.2.11": true},
	}
	for ip, want := range map[string]bool{
		"192.0.2.10": true, "192.0.2.11": true, "192.0.2.12": true,
		"192.0.2.13": false, "192.0.2.14": false,
	} {
		if got := db.IsWhitelisted(ip); got != want {
			t.Errorf("IsWhitelisted(%s) = %v, want %v", ip, got, want)
		}
	}
}
