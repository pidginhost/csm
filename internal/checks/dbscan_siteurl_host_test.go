package checks

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// A hijack that keeps a clean URL shape passes siteURLPoisonReason: the
// karmaboutique poisoning was caught only because it carried a query string.
// The host is the stronger signal -- but on its own it reports every migrated
// site, which is why siteURLPoisonReason deliberately does not test it.
//
// The served state resolves that. A root the panel serves under domains the
// account owns, whose WordPress address points somewhere unrelated, is not a
// migration: a migrated site is no longer served here.

func siteurlHostFinding(t *testing.T, value string, served servedState, owned ...string) *alert.Finding {
	t.Helper()
	creds := wpDBCreds{dbName: "wp", docrootServed: served, accountDomains: owned}
	return foreignSiteURLFinding("alice", creds, "wp_", "siteurl", value)
}

func TestForeignSiteURL_ServedRootPointingOffAccount(t *testing.T) {
	got := siteurlHostFinding(t, "https://slow.destinyfernandi.example/", servedByPanel, "karmaboutique.example")

	if got == nil {
		t.Fatal("a served root addressed at an unowned domain must be reported")
	}
	if got.Check != "db_siteurl_foreign_host" {
		t.Errorf("check = %q", got.Check)
	}
	if !strings.Contains(got.Details, "destinyfernandi.example") {
		t.Errorf("details must name the address, got:\n%s", got.Details)
	}
}

// The account's own domains are fine, including a subdomain of one.
func TestForeignSiteURL_OwnedDomainsAreSilent(t *testing.T) {
	for _, value := range []string{
		"https://karmaboutique.example/",
		"https://www.karmaboutique.example/shop",
		"https://shop.karmaboutique.example/",
		"http://second.example/",
		// cPanel lists a subdomain as its own domain, so the account's list can
		// hold a name that is not itself a registrable domain. The site
		// addressing the parent must still be recognised as its own.
		"https://karmaboutique.example/",
	} {
		if got := siteurlHostFinding(t, value, servedByPanel, "shop.karmaboutique.example", "second.example"); got != nil {
			t.Errorf("owned address %q reported: %s", value, got.Message)
		}
	}
}

// The documented false positive: a site that moved away is no longer served
// here, so an unowned address is expected rather than suspicious.
func TestForeignSiteURL_DormantRootStaysSilent(t *testing.T) {
	if got := siteurlHostFinding(t, "https://moved-elsewhere.example/", notServed, "karmaboutique.example"); got != nil {
		t.Fatalf("migrated site on an unserved root reported: %s", got.Message)
	}
}

// Without the panel's map we do not know whether it is served, so the
// migration explanation cannot be ruled out.
func TestForeignSiteURL_UnknownServedStateStaysSilent(t *testing.T) {
	if got := siteurlHostFinding(t, "https://elsewhere.example/", servedUnknown, "karmaboutique.example"); got != nil {
		t.Fatalf("unknown served state reported: %s", got.Message)
	}
}

// Knowing no domains means the comparison has no basis at all.
func TestForeignSiteURL_NoKnownDomainsStaysSilent(t *testing.T) {
	if got := siteurlHostFinding(t, "https://elsewhere.example/", servedByPanel); got != nil {
		t.Fatalf("reported without knowing which domains the account owns: %s", got.Message)
	}
}

// Shape problems are siteURLPoisonReason's job and are already reported; this
// check must not raise a second finding about the same value.
func TestForeignSiteURL_LeavesMalformedValuesToTheShapeCheck(t *testing.T) {
	for _, value := range []string{
		"", "not a url", "javascript:alert(1)", "https:///nohost",
		// The live poisoning: an unowned host AND a query string. The shape
		// check already reports this one, so reporting it again adds nothing.
		"https://slow.destinyfernandi.example/hos?/pret.js?l=1",
		"https://slow.destinyfernandi.example/x#frag",
	} {
		if got := siteurlHostFinding(t, value, servedByPanel, "karmaboutique.example"); got != nil {
			t.Errorf("malformed value %q double-reported: %s", value, got.Message)
		}
	}
}
