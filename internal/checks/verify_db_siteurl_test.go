package checks

import (
	"strings"
	"testing"
)

// A re-check has to apply the same rule the detector does. Otherwise the
// operator clicks Re-check on a poisoned siteurl, the verifier finds no
// eval()/<script>, and CSM dismisses a live compromise as resolved.
func TestSiteurlValueStillMaliciousCoversPoisonedAddresses(t *testing.T) {
	malicious := []string{
		"https://slow.destinyfernandi.com/hos?/pret.js?l=1",
		"https://cdn.example.net/loader.js",
		"data:text/html;base64,PHNjcmlwdD4=",
		"https://example.com/x.php",
		"https://example.com/x.phtml",
		`https://example.com/path\loader`,
		"https://example.com/<script>x</script>",
	}
	for _, v := range malicious {
		if !siteurlValueStillMalicious(v) {
			t.Errorf("verifier resolved poisoned siteurl %q", v)
		}
	}

	clean := []string{
		"https://example.com",
		"https://example.com/blog",
		"http://www.example.com/trailere",
		"https://example.com:8443",
	}
	for _, v := range clean {
		if siteurlValueStillMalicious(v) {
			t.Errorf("verifier kept clean siteurl %q open", v)
		}
	}
}

func TestVerifyDBSiteurlHijackKeepsPoisonedAddressOpen(t *testing.T) {
	withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
	withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
		return []string{"https://slow.destinyfernandi.com/hos?/pret.js?l=1"}, nil
	})

	res := verifyDBSiteurlHijack(
		"WordPress siteurl is not a site address (account: alice): address carries a query string",
		"Database: alice_wp\nTable prefix: wp_\nsiteurl = https://slow.destinyfernandi.com/hos?/pret.js?l=1",
	)
	if !res.Checked || res.Resolved {
		t.Fatalf("want checked and unresolved, got %+v", res)
	}
	if !strings.Contains(res.Detail, "poisoned site address") {
		t.Fatalf("re-check detail must describe the address finding, got %q", res.Detail)
	}
}
