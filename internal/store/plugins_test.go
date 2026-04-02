package store

import (
	"testing"
	"time"
)

func TestSetGetPluginInfo(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	info := PluginInfo{
		LatestVersion: "3.2.1",
		TestedUpTo:    "6.5",
		LastChecked:   time.Now().Unix(),
	}

	// Set plugin info.
	if err := db.SetPluginInfo("akismet", info); err != nil {
		t.Fatalf("SetPluginInfo: %v", err)
	}

	// Get it back and verify fields.
	got, found := db.GetPluginInfo("akismet")
	if !found {
		t.Fatal("GetPluginInfo(akismet): not found")
	}
	if got.LatestVersion != "3.2.1" {
		t.Fatalf("LatestVersion = %q, want %q", got.LatestVersion, "3.2.1")
	}
	if got.TestedUpTo != "6.5" {
		t.Fatalf("TestedUpTo = %q, want %q", got.TestedUpTo, "6.5")
	}
	if got.LastChecked != info.LastChecked {
		t.Fatalf("LastChecked = %d, want %d", got.LastChecked, info.LastChecked)
	}

	// Get nonexistent slug — not found.
	_, found = db.GetPluginInfo("nonexistent-plugin")
	if found {
		t.Fatal("GetPluginInfo(nonexistent-plugin) should not be found")
	}
}

func TestSetGetSitePlugins(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	site := SitePlugins{
		Account: "user1",
		Domain:  "example.com",
		Plugins: []SitePluginEntry{
			{
				Slug:             "akismet",
				Name:             "Akismet Anti-Spam",
				Status:           "active",
				InstalledVersion: "3.1.0",
				UpdateVersion:    "3.2.1",
			},
			{
				Slug:             "woocommerce",
				Name:             "WooCommerce",
				Status:           "inactive",
				InstalledVersion: "8.0.0",
				UpdateVersion:    "",
			},
		},
	}

	wpPath := "/home/user1/public_html/wp-content"

	// Set site plugins.
	if err := db.SetSitePlugins(wpPath, site); err != nil {
		t.Fatalf("SetSitePlugins: %v", err)
	}

	// Get it back and verify.
	got, found := db.GetSitePlugins(wpPath)
	if !found {
		t.Fatal("GetSitePlugins: not found")
	}
	if got.Account != "user1" {
		t.Fatalf("Account = %q, want %q", got.Account, "user1")
	}
	if got.Domain != "example.com" {
		t.Fatalf("Domain = %q, want %q", got.Domain, "example.com")
	}
	if len(got.Plugins) != 2 {
		t.Fatalf("len(Plugins) = %d, want 2", len(got.Plugins))
	}
	if got.Plugins[0].Slug != "akismet" {
		t.Fatalf("Plugins[0].Slug = %q, want %q", got.Plugins[0].Slug, "akismet")
	}
	if got.Plugins[1].Status != "inactive" {
		t.Fatalf("Plugins[1].Status = %q, want %q", got.Plugins[1].Status, "inactive")
	}

	// Get nonexistent path — not found.
	_, found = db.GetSitePlugins("/nonexistent/path")
	if found {
		t.Fatal("GetSitePlugins(/nonexistent/path) should not be found")
	}
}

func TestDeleteSitePlugins(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	site1 := SitePlugins{Account: "user1", Domain: "site1.com"}
	site2 := SitePlugins{Account: "user2", Domain: "site2.com"}

	path1 := "/home/user1/public_html/wp-content"
	path2 := "/home/user2/public_html/wp-content"

	if err := db.SetSitePlugins(path1, site1); err != nil {
		t.Fatalf("SetSitePlugins(path1): %v", err)
	}
	if err := db.SetSitePlugins(path2, site2); err != nil {
		t.Fatalf("SetSitePlugins(path2): %v", err)
	}

	// Delete site1.
	if err := db.DeleteSitePlugins(path1); err != nil {
		t.Fatalf("DeleteSitePlugins: %v", err)
	}

	// Verify site1 is gone.
	_, found := db.GetSitePlugins(path1)
	if found {
		t.Fatal("site1 should be deleted")
	}

	// Verify site2 still exists.
	got, found := db.GetSitePlugins(path2)
	if !found {
		t.Fatal("site2 should still exist")
	}
	if got.Domain != "site2.com" {
		t.Fatalf("Domain = %q, want %q", got.Domain, "site2.com")
	}
}

func TestAllSitePlugins(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	site1 := SitePlugins{Account: "user1", Domain: "site1.com"}
	site2 := SitePlugins{Account: "user2", Domain: "site2.com"}

	path1 := "/home/user1/public_html/wp-content"
	path2 := "/home/user2/public_html/wp-content"

	if err := db.SetSitePlugins(path1, site1); err != nil {
		t.Fatalf("SetSitePlugins(path1): %v", err)
	}
	if err := db.SetSitePlugins(path2, site2); err != nil {
		t.Fatalf("SetSitePlugins(path2): %v", err)
	}

	all := db.AllSitePlugins()
	if len(all) != 2 {
		t.Fatalf("len(AllSitePlugins) = %d, want 2", len(all))
	}
	if all[path1].Domain != "site1.com" {
		t.Fatalf("all[path1].Domain = %q, want %q", all[path1].Domain, "site1.com")
	}
	if all[path2].Domain != "site2.com" {
		t.Fatalf("all[path2].Domain = %q, want %q", all[path2].Domain, "site2.com")
	}
}

func TestPluginRefreshTime(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Initially should be zero.
	got := db.GetPluginRefreshTime()
	if !got.IsZero() {
		t.Fatalf("initial GetPluginRefreshTime = %v, want zero", got)
	}

	// Set and get back.
	now := time.Now().Truncate(time.Second)
	if err := db.SetPluginRefreshTime(now); err != nil {
		t.Fatalf("SetPluginRefreshTime: %v", err)
	}

	got = db.GetPluginRefreshTime()
	if !got.Equal(now) {
		t.Fatalf("GetPluginRefreshTime = %v, want %v", got, now)
	}
}
