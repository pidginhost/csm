package checks

import "testing"

// A re-check has to apply the same rule the detector does. Otherwise the
// operator clicks Re-check on a poisoned siteurl, the verifier finds no
// eval()/<script>, and CSM dismisses a live compromise as resolved.
func TestSiteurlValueStillMaliciousCoversPoisonedAddresses(t *testing.T) {
	malicious := []string{
		"https://slow.destinyfernandi.com/hos?/pret.js?l=1",
		"https://cdn.example.net/loader.js",
		"data:text/html;base64,PHNjcmlwdD4=",
		"https://example.com/x.php",
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
