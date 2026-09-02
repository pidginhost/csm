package checks

import "testing"

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
