//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"golang.org/x/sys/unix"
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
		{"default account roots", nil, "/home3/alice/mail/evil.php"},
		{"mail named account", []string{"/home/*"}, "/home/mail/mail/evil.php"},
		{"mail in account root", []string{"/srv/mail/*"}, "/srv/mail/alice/mail/evil.php"},
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
		{"empty account component", []string{"/home/*"}, "/home//mail/index.php"},
		{"different root case", []string{"/home/*"}, "/Home/alice/mail/index.php"},
		{"different mail case", []string{"/home/*"}, "/home/alice/Mail/index.php"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := analyzeMailDirProbe(t, tc.roots, tc.path); len(got) != 0 {
				t.Fatalf("got %+v, want no findings for an inert PHP stub", got)
			}
		})
	}
}

func TestNestedMailDirectoryStillScansPHP(t *testing.T) {
	useRealtimeRules(t, realtimeHighRule)
	probe := filepath.Join(t.TempDir(), "probe.php")
	if err := os.WriteFile(probe, []byte("<?php echo 'EVIL_MARKER_A'; ?>"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := "/home/alice/public_html/wp-content/plugins/newsletter/vendor/icons/mail/index.php"
	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch, accountRootPatterns: []string{"/home/*"}}
	fd := openRawFd(t, probe)
	if !fm.isInteresting(path) || !fm.tempRootEventNeedsAnalysis(path, fd) {
		t.Fatal("nested mail directory bypassed PHP admission")
	}
	fm.analyzeFile(fileEvent{path: path, fd: fd})
	got := drainFindings(ch)
	if len(got) != 1 || got[0].Check != "signature_match_realtime" || got[0].Severity != alert.High || got[0].FilePath != path {
		t.Fatalf("got %+v, want one High content finding at %s", got, path)
	}
}

// The reader's interest filter must admit what the analyzer reports.
func TestIsInterestingAdmitsPHPInFurtherHomePartitionMailDir(t *testing.T) {
	fm := &FileMonitor{cfg: &config.Config{}, accountRootPatterns: []string{"/home/*"}}
	if !fm.isInteresting("/home2/alice/mail/evil.php") {
		t.Error("isInteresting = false for PHP in an account mail directory on /home2")
	}
}

func TestAccountMailPathNormalization(t *testing.T) {
	for _, path := range []string{
		"/home//alice/mail/probe.php",
		"/home/alice//mail/probe.php",
		"/home2//alice/mail/probe.php",
		"/home/alice//mail/.temp.123.probe.PHP",
	} {
		t.Run(path, func(t *testing.T) {
			got := analyzeMailDirProbe(t, []string{"/home/*"}, path)
			if len(got) != 1 || got[0].Check != "php_in_sensitive_dir_realtime" || got[0].Severity != alert.Critical || got[0].FilePath != path {
				t.Fatalf("got %+v, want one Critical sensitive-directory finding at %s", got, path)
			}
		})
	}
}

// Exercise the descriptor path used by the reader. Linux resolves symlinks
// and redundant separators before exposing that path through procfs.
func TestAccountMailReaderPathParity(t *testing.T) {
	t.Setenv("TMPDIR", "/tmp")
	for _, tc := range []struct {
		name      string
		targetDir string
		linkDir   string
		critical  bool
	}{
		{name: "direct", targetDir: "alice/mail", critical: true},
		{name: "case sensitive account", targetDir: "Alice/mail", critical: true},
		{name: "symlink into mail", targetDir: "alice/mail", linkDir: "alice/public_html/alias", critical: true},
		{name: "symlink with dot dot", targetDir: "alice/mail", linkDir: "alice/public_html/alias", critical: true},
		{name: "nested mail", targetDir: "alice/public_html/vendor/icons/mail"},
		{name: "symlink to nested mail", targetDir: "alice/public_html/vendor/icons/mail", linkDir: "alice/alias"},
		{name: "different directory case", targetDir: "alice/Mail"},
		{name: "mail account", targetDir: "mail/mail", critical: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, name := range []string{"probe.php", "probe.PHP", ".temp.123.probe.PHP"} {
				t.Run(name, func(t *testing.T) {
					root := t.TempDir()
					dir := filepath.Join(root, tc.targetDir)
					if err := os.MkdirAll(filepath.Join(dir, "child"), 0o755); err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(dir, name)
					if err := os.WriteFile(path, []byte("<?php\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					openedPath := path
					if tc.linkDir != "" {
						link := filepath.Join(root, tc.linkDir)
						if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(dir, link); err != nil {
							t.Fatal(err)
						}
						openedPath = link + "/" + name
						if tc.name == "symlink with dot dot" {
							openedPath = link + "/child/../" + name
						}
					}
					openedPath = strings.ReplaceAll(openedPath, "/", "//")
					ch := make(chan alert.Finding, 8)
					fm := &FileMonitor{
						cfg: &config.Config{}, alertCh: ch, analyzerCh: make(chan fileEvent, 1),
						accountRootPatterns: []string{filepath.Join(root, "*")},
					}
					fd := openRawFd(t, openedPath)
					if !fm.isInteresting(path) || !fm.tempRootEventNeedsAnalysis(path, fd) {
						t.Fatal("PHP event was rejected by an admission gate")
					}
					dup, err := unix.Dup(fd)
					if err != nil {
						t.Fatal(err)
					}
					fm.handleEvent(dup, 0, FAN_CLOSE_WRITE)
					select {
					case event := <-fm.analyzerCh:
						defer func() { _ = unix.Close(event.fd) }()
						if event.path != path || event.dropperOnly {
							t.Fatalf("queued path=%q dropperOnly=%v, want content analysis at %q", event.path, event.dropperOnly, path)
						}
						fm.analyzeFile(event)
					default:
						assertFDClosed(t, dup, "rejected mail event")
						t.Fatal("PHP event was not queued")
					}
					got := drainFindings(ch)
					if tc.critical {
						if len(got) != 1 || got[0].Check != "php_in_sensitive_dir_realtime" || got[0].Severity != alert.Critical || got[0].FilePath != path {
							t.Fatalf("got %+v, want one Critical sensitive-directory finding at %s", got, path)
						}
					} else if len(got) != 0 {
						t.Fatalf("got %+v for an inert PHP stub outside an account mail store", got)
					}
				})
			}
		})
	}
}
