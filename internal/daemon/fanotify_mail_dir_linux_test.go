//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// PHP never belongs in an account's mail directory, but "mail" is also an
// ordinary directory name inside web applications: a newsletter plugin ships
// vendor/.../icons/mail/index.php. Only the mail directory directly inside an
// account home is a location that makes PHP Critical on its own.

func analyzeMailDirProbe(t *testing.T, accountRoots []string, path string) []alert.Finding {
	t.Helper()
	probe := filepath.Join(t.TempDir(), "probe.php")
	if err := os.WriteFile(probe, []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch, accountRootPatterns: accountRoots}
	fm.analyzeFile(fileEvent{path: path, fd: openRawFd(t, probe)})
	return drainFindings(ch)
}

func TestPHPInAccountMailDirIsCritical(t *testing.T) {
	cases := []struct {
		name  string
		roots []string
		path  string
	}{
		{"mail root", []string{"/home/*"}, "/home/alice/mail/evil.php"},
		{"mailbox folder", []string{"/home/*"}, "/home/alice/mail/example.com/info/cur/evil.php"},
		{"further cPanel home partition", []string{"/home/*"}, "/home2/alice/mail/evil.php"},
		{"platform account root", []string{"/var/www/vhosts/*"}, "/var/www/vhosts/example.com/mail/evil.php"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := analyzeMailDirProbe(t, tc.roots, tc.path)
			if len(got) != 1 || got[0].Check != "php_in_sensitive_dir_realtime" || got[0].Severity != alert.Critical {
				t.Fatalf("got %+v, want one Critical php_in_sensitive_dir_realtime", got)
			}
		})
	}
}

func TestPHPInNestedMailDirectoryIsNotSensitive(t *testing.T) {
	cases := []struct {
		name  string
		roots []string
		path  string
	}{
		{"plugin vendor icons", []string{"/home/*"}, "/home/alice/public_html/wp-content/plugins/newsletter/vendor/editor/icons/mail/index.php"},
		{"webmail app in a document root", []string{"/home/*"}, "/home/alice/public_html/mail/index.php"},
		{"lookalike home partition", []string{"/home/*"}, "/homework/alice/mail/index.php"},
		{"home outside the platform account roots", []string{"/var/www/vhosts/*"}, "/home/alice/mail/index.php"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range analyzeMailDirProbe(t, tc.roots, tc.path) {
				if f.Check == "php_in_sensitive_dir_realtime" {
					t.Fatalf("got %+v, want no sensitive-directory finding", f)
				}
			}
		})
	}
}

// The reader's interest filter must admit what the analyzer reports.
func TestIsInterestingAdmitsPHPInFurtherHomePartitionMailDir(t *testing.T) {
	fm := &FileMonitor{cfg: &config.Config{}, accountRootPatterns: []string{"/home/*"}}
	if !fm.isInteresting("/home2/alice/mail/evil.php") {
		t.Error("isInteresting = false for PHP in an account mail directory on /home2")
	}
}
