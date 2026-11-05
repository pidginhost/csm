package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

func FuzzPHPRelayStaffRequest(f *testing.F) {
	for _, target := range []string{
		"", "/wp-admin/edit.php", "/wp-admin/load-styles.php?c=1",
		"/wp-admin/admin%2Dajax.php?action=heartbeat",
		"/wp-admin/edit.php/../../wp-login.php",
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
