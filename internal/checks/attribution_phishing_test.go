package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// writePhishingFixtures lays out one file per phishing detector under a
// document root. Every detector reads the file it names, so each finding
// carries a path under the owning account.
func writePhishingFixtures(t *testing.T, docroot string) {
	t.Helper()
	files := map[string]string{
		// Brand page padded past the 3 KB acceptance floor.
		"verify.html": officePhishHTML + strings.Repeat(" ", 3500),
		// Tiny full-screen iframe onto an external host.
		"redir.html": `<html><body><iframe src="https://evil.example/phish" width="100%" height="100%"></iframe></body></html>`,
		// Body-branded PHP kit that captures a password, padded past 3 KB.
		"shared-document.php": `<?php
$email = $_POST['email'];
$password = $_POST['password'];
file_put_contents('results.txt', "$email:$password\n", FILE_APPEND);
?>
<html><body>
<img src="dropbox-logo.png" alt="Dropbox">
<p>Open the shared folder</p>
<form method="post">
<input type="email" name="email">
<input type="password" name="password">
</form>
</body></html>` + strings.Repeat(" ", 3500),
		// Open redirector under 1 KB.
		"go.php": `<?php header("Location: ".$_GET['url']); ?>`,
		// Harvested credential dump under a kit's canonical name.
		"results.txt": "alice@example.com:Passw0rd\nbob@example.com|s3cret\ncarol@example.com,hunter2\n",
		// Lone credential page in a business-named folder.
		"AcmeHoldings/verify.html": officePhishHTML + strings.Repeat(" ", 3500),
	}
	for rel, body := range files {
		path := filepath.Join(docroot, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil { // #nosec G306 -- fixture must be world-readable like a docroot
			t.Fatal(err)
		}
	}
	writeKitTestZip(t, filepath.Join(docroot, "office365.zip"), []string{
		"office365/login.html",
		"office365/next.php",
		"office365/results.txt",
	})
}

// Every phishing detector names the file it judged, so correlation resolves
// the owner from the path and the Critical families count toward the
// cross-account aggregate.
func TestPhishingFindingsAttributeByPath(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	docroot := filepath.Join(root, "alice", "public_html")
	writePhishingFixtures(t, docroot)

	var findings []alert.Finding
	scanForPhishing(context.Background(), docroot, phishingScanMaxDepth, "alice", &config.Config{}, &findings)
	seen := expectAttributed(t, findings, "alice")
	requireChecks(t, seen,
		"phishing_page", "phishing_iframe", "phishing_php", "phishing_redirector",
		"phishing_credential_log", "phishing_kit_archive", "phishing_directory")

	anchors := []alert.Finding{critical("db_rogue_admin", "bob"), critical("db_rogue_admin", "carol")}
	res := CorrelateFindings(append(anchors, findings...))
	if len(res.Derived) != 1 || res.Derived[0].Check != "coordinated_attack" {
		t.Fatalf("critical phishing output did not aggregate: %+v", res)
	}
	if len(res.Unattributed) != 0 {
		t.Fatalf("unattributed phishing rows %v", res.Unattributed)
	}
}
