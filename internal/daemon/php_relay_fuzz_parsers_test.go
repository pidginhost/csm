package daemon

import (
	"net/url"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

func FuzzPHPRelayStaffRequest(f *testing.F) {
	for _, target := range []string{
		"", "/wp-admin/edit.php", "/wp-admin/load-styles.php?c=1",
		"/wp-admin/admin%2Dajax.php?action=heartbeat",
		"/wp-admin/edit.php/../../wp-login.php",
		"/wp-admin/admin.php?page=wc-orders",
		"/wp-admin/admin.php?page=wc-orders--shop_subscription",
		"/wp-admin/admin.php?page=wc-orders&page%00=subscriber-dashboard",
		"https://site.example/shop/wp-admin/edit.php?return=%2Fshop",
	} {
		f.Add(target)
	}
	f.Fuzz(func(t *testing.T, target string) {
		rec := checks.CrawlLogRecord{Method: "GET", Status: 200, Target: target}
		_ = isStaffAdminRequest(rec)
		// An ambiguous path must stay ineligible regardless of its suffix.
		for _, prefix := range []string{"/%2e/", "/./", "/../", "/wp-admin/edit.php/"} {
			rec.Target = prefix + target
			if isStaffAdminRequest(rec) {
				t.Fatalf("ambiguous request granted staff evidence: %q", rec.Target)
			}
		}
	})
}

func FuzzPHPRelayOrderListQuery(f *testing.F) {
	for _, suffix := range []string{"", "ignored", "[]", "\x00", " &page=wc-orders"} {
		f.Add(suffix)
	}
	f.Fuzz(func(t *testing.T, suffix string) {
		rec := checks.CrawlLogRecord{Method: "GET", Status: 200}
		for _, name := range []string{"page", " page", "page\x00" + suffix, " page\x00" + suffix, "page[" + suffix + "]"} {
			rec.Target = "/wp-admin/admin.php?page=wc-orders&" + url.QueryEscape(name) + "=subscriber-dashboard"
			if isStaffAdminRequest(rec) {
				t.Fatalf("PHP page override granted staff evidence: %q", rec.Target)
			}
		}
		// Any preceding parameter can consume the site's input limit.
		rec.Target = "/wp-admin/admin.php?" + url.QueryEscape(suffix) + "=x&page=wc-orders"
		if isStaffAdminRequest(rec) {
			t.Fatalf("nonleading page granted staff evidence: %q", rec.Target)
		}
	})
}
