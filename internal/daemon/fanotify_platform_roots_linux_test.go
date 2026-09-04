//go:build linux

package daemon

import "testing"

// On Plesk and DirectAdmin an account tree is not /home/<user> and a document
// root is not public_html. Every one of these detectors was gated on the cPanel
// spelling, so realtime phishing, credential-log, ZIP and CGI detection was
// dead on those platforms even with account_roots configured.
func TestIsInteresting_HonoursConfiguredAccountRoots(t *testing.T) {
	fm := &FileMonitor{
		accountRootPatterns: []string{"/var/www/vhosts/*"},
		docRootPatterns:     []string{"/var/www/vhosts/*/httpdocs"},
	}

	for _, tc := range []struct {
		desc string
		path string
		want bool
	}{
		{"perl CGI in an account tree", "/var/www/vhosts/site.example/cgi-bin/shell.pl", true},
		{"phishing HTML in an account tree", "/var/www/vhosts/site.example/httpdocs/login.html", true},
		{"phishing kit archive in an account tree", "/var/www/vhosts/site.example/httpdocs/office365-login.zip", true},
		{"unrelated tree stays uninteresting", "/opt/vendor/tool/readme.html", false},
	} {
		if got := fm.isInteresting(tc.path); got != tc.want {
			t.Errorf("%s: isInteresting(%q) = %v, want %v", tc.desc, tc.path, got, tc.want)
		}
	}
}

// The document-root gate on the phishing, credential-log and ZIP analyzers must
// follow the configured roots too, not the literal string "/public_html/".
func TestUnderDocRoot_FollowsConfiguredRoots(t *testing.T) {
	fm := &FileMonitor{docRootPatterns: []string{"/var/www/vhosts/*/httpdocs"}}

	if !fm.underDocRoot("/var/www/vhosts/site.example/httpdocs/wp-login.html") {
		t.Error("configured document root not recognised")
	}
	if fm.underDocRoot("/var/www/vhosts/site.example/private/notes.html") {
		t.Error("path outside the document root was accepted")
	}
}

// A host with no configuration and no panel keeps the historical behaviour:
// these detectors were written for /home and must not go silent there.
func TestUnderRoots_FallBackToLegacySpelling(t *testing.T) {
	fm := &FileMonitor{}

	if !fm.underAccountRoot("/home/alice/public_html/shell.pl") {
		t.Error("legacy /home account-root spelling lost")
	}
	if !fm.underDocRoot("/home/alice/public_html/login.html") {
		t.Error("legacy /public_html document-root spelling lost")
	}
	if fm.underAccountRoot("/var/lib/mysql/data.ibd") {
		t.Error("unrelated path treated as an account tree")
	}
}
