package checks

import (
	"net"
	"reflect"
	"testing"
	"time"
)

func TestThreatDBMapSources(t *testing.T) {
	_, drop, _ := net.ParseCIDR("198.51.100.0/24")
	db := &ThreatDB{
		badIPs: map[string]string{
			"203.0.113.1": "permanent-blocklist",
			"203.0.113.2": "auto-block",
			"203.0.113.3": "blocklist-de",
		},
		badIPExpiry: map[string]time.Time{"203.0.113.2": time.Now().Add(time.Hour)},
		feedIPs: map[string]map[string]struct{}{
			"blocklist-de": {"203.0.113.3": {}},
			"cins-army":    {"203.0.113.4": {}},
		},
		feedNets:        map[string][]*net.IPNet{"spamhaus-drop": {drop}},
		whitelist:       map[string]bool{"192.0.2.10": true},
		configWhitelist: map[string]bool{"192.0.2.11": true},
		whitelistMeta:   map[string]*whitelistEntry{},
	}
	got := db.MapSources()
	want := ThreatMapSources{
		Permanent: []string{"203.0.113.1"},
		FeedIPs:   map[string][]string{"blocklist-de": {"203.0.113.3"}, "cins-army": {"203.0.113.4"}},
		FeedNets:  map[string][]string{"spamhaus-drop": {"198.51.100.0/24"}},
		Whitelist: []string{"192.0.2.10", "192.0.2.11"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MapSources = %+v\nwant %+v", got, want)
	}
}
