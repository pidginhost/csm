package checks

import (
	"testing"
	"time"
)

// reputation.whitelist is a hot-reloadable field, but the threat DB copied it
// once at construction, so a SIGHUP reported success while lookups kept the
// startup list. The config whitelist is a replaceable set distinct from the
// operator-managed (persisted) entries.
func TestThreatDBSetConfigWhitelistReplacesConfiguredEntries(t *testing.T) {
	restore := SetGlobalThreatDBForTest(t.TempDir())
	defer restore()
	db := GetThreatDB()
	db.AddPermanent("203.0.113.9", "test-feed")
	db.AddWhitelist("203.0.113.10")

	db.SetConfigWhitelist([]string{"203.0.113.9"})
	if _, found := db.Lookup("203.0.113.9"); found {
		t.Fatal("IP added to reputation.whitelist is still flagged")
	}

	db.SetConfigWhitelist(nil)
	if _, found := db.Lookup("203.0.113.9"); !found {
		t.Fatal("IP removed from reputation.whitelist stays whitelisted after reload")
	}
	var operatorEntryKept bool
	for _, w := range db.WhitelistedIPs() {
		if w.IP == "203.0.113.10" {
			operatorEntryKept = true
		}
	}
	if !operatorEntryKept {
		t.Fatal("operator-managed whitelist entry was dropped when the config whitelist was replaced")
	}
}

func TestConfiguredWhitelistEntriesRemainConfigManaged(t *testing.T) {
	restore := SetGlobalThreatDBForTest(t.TempDir())
	defer restore()
	db := GetThreatDB()
	db.SetConfigWhitelist([]string{" 2001:DB8::1 ", "not-an-ip"})
	db.AddWhitelist("203.0.113.10")
	db.TempWhitelist("203.0.113.11", time.Hour)

	db.RemoveWhitelist("2001:db8::1")
	if !db.IsConfigWhitelisted("2001:db8::1") {
		t.Fatal("runtime removal deleted a config-managed entry")
	}

	entries := db.WhitelistedIPs()
	byIP := make(map[string]WhitelistIP, len(entries))
	for _, entry := range entries {
		byIP[entry.IP] = entry
	}
	configured, ok := byIP["2001:db8::1"]
	if !ok || !configured.Configured || configured.Permanent || configured.ExpiresAt != nil {
		t.Fatalf("configured entry metadata = %+v, want configured-only", configured)
	}
	if _, ok := byIP["not-an-ip"]; ok {
		t.Fatal("invalid configured whitelist entry was published")
	}
	if got := db.Stats()["whitelist"]; got != 3 {
		t.Fatalf("whitelist stats = %v, want 3 unique entries", got)
	}
}
