package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// inheritFixture stages one cPanel account on disk: the domain map, a passwd
// entry, and the account home. Everything is read through the production
// filesystem provider so the tenant-file boundary is exercised for real.
type inheritFixture struct {
	t     *testing.T
	owner string
	root  string
	home  string
}

func newInheritFixture(t *testing.T, owner string) *inheritFixture {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home", owner)
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, realOS{})
	withMockPasswd(t, fmt.Sprintf("%s:x:1001:1001::%s:/bin/bash\n", owner, home))
	withInstalledPHPBins(t)
	return &inheritFixture{t: t, owner: owner, root: root, home: home}
}

// domainMap writes /etc/userdatadomains rows. "%HOME%" in a row expands to
// the account home.
func (f *inheritFixture) domainMap(rows ...string) {
	f.t.Helper()
	path := filepath.Join(f.root, "userdatadomains")
	content := strings.ReplaceAll(strings.Join(rows, "\n")+"\n", "%HOME%", f.home)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		f.t.Fatal(err)
	}
	prev := userdataDomainsPath
	userdataDomainsPath = path
	f.t.Cleanup(func() { userdataDomainsPath = prev })
}

func (f *inheritFixture) dir(rel string) string {
	f.t.Helper()
	d := filepath.Join(f.home, rel)
	if err := os.MkdirAll(d, 0o755); err != nil {
		f.t.Fatal(err)
	}
	return d
}

func (f *inheritFixture) htaccess(dir, content string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func withInstalledPHPBins(t *testing.T, bins ...string) {
	t.Helper()
	installed := map[string]bool{}
	for _, b := range bins {
		installed[b] = true
	}
	prev := wpCronPHPBinInstalled
	wpCronPHPBinInstalled = func(bin string) bool { return installed[bin] }
	t.Cleanup(func() { wpCronPHPBinInstalled = prev })
}

// cpanelHandlerBlock is the block MultiPHP Manager writes into a docroot
// .htaccess. LiteSpeed hosts carry the ___lsphp suffix, Apache hosts do not.
func cpanelHandlerBlock(version, suffix string) string {
	return "# php -- BEGIN cPanel-generated handler, do not edit\n" +
		"# Set the \"" + version + "\" package as the default \"PHP\" programming language.\n" +
		"<IfModule mime_module>\n" +
		"  AddHandler application/x-httpd-" + version + suffix + " .php .php7 .phtml\n" +
		"</IfModule>\n" +
		"# php -- END cPanel-generated handler, do not edit\n"
}

const wpRewriteBlock = "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteRule ^index\\.php$ - [L]\n</IfModule>\n# END WordPress\n"

// An inheriting vhost runs whatever handler the web server finds in the
// .htaccess chain, not the system default the domain map implies. A cPanel
// handler block left in the docroot pins the site to that version, so
// WP-Cron must run under it too; driven by a newer default instead, an old
// site logs a flood of deprecations on every run.
func TestResolveDocrootPHPBinInheritFollowsDocrootHandler(t *testing.T) {
	for _, tc := range []struct {
		name, column, version, suffix, want string
	}{
		{"empty column, LiteSpeed handler", "", "ea-php73", "___lsphp", "/opt/cpanel/ea-php73/root/usr/bin/php"},
		{"literal inherit, Apache handler", "inherit", "ea-php74", "", "/opt/cpanel/ea-php74/root/usr/bin/php"},
		{"CloudLinux alt-php handler", "", "alt-php56", "___lsphp", "/opt/alt/php56/usr/bin/php"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInheritFixture(t, "alice")
			f.domainMap("site.example.com: alice==root==addon==main.example.com==%HOME%/site.example.com==192.0.2.10:80==192.0.2.10:443====0==" + tc.column)
			docroot := f.dir("site.example.com")
			f.htaccess(docroot, wpRewriteBlock+cpanelHandlerBlock(tc.version, tc.suffix))
			withInstalledPHPBins(t, tc.want)

			if got := resolveDocrootPHPBin("alice", docroot); got != tc.want {
				t.Errorf("resolveDocrootPHPBin() = %q, want %q", got, tc.want)
			}
		})
	}
}

// Apache applies every .htaccess from the account home down, so an
// inheriting subdomain nested under public_html runs the handler written for
// the main site, and a WordPress install below a docroot runs its vhost's.
func TestResolveDocrootPHPBinInheritFollowsAncestorHandler(t *testing.T) {
	const php81 = "/opt/cpanel/ea-php81/root/usr/bin/php"
	for _, tc := range []struct {
		name, handlerDir, target string
	}{
		{"subdomain under public_html", "public_html", "public_html/sub"},
		{"WordPress below an inheriting docroot", "public_html/sub", "public_html/sub/blog"},
		{"handler in the account home", "", "public_html/sub"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInheritFixture(t, "alice")
			f.domainMap(
				"example.com: alice==root==main==example.com==%HOME%/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php81",
				"sub.example.com: alice==root==sub==example.com==%HOME%/public_html/sub==192.0.2.10:80==192.0.2.10:443====0==",
			)
			target := f.dir(tc.target)
			f.htaccess(f.dir(tc.handlerDir), cpanelHandlerBlock("ea-php81", "___lsphp"))
			withInstalledPHPBins(t, php81)

			if got := resolveDocrootPHPBin("alice", target); got != php81 {
				t.Errorf("resolveDocrootPHPBin(%q) = %q, want %q", target, got, php81)
			}
		})
	}
}

// The nearest block governs, and within one file the last AddHandler for .php
// wins, matching how the web server applies the directives.
func TestResolveDocrootPHPBinInheritNearestAndLastHandlerWins(t *testing.T) {
	f := newInheritFixture(t, "alice")
	f.domainMap("sub.example.com: alice==root==sub==example.com==%HOME%/public_html/sub==192.0.2.10:80==192.0.2.10:443====0==")
	f.htaccess(f.dir("public_html"), cpanelHandlerBlock("ea-php81", "___lsphp"))
	docroot := f.dir("public_html/sub")
	f.htaccess(docroot, cpanelHandlerBlock("ea-php80", "___lsphp")+wpRewriteBlock+cpanelHandlerBlock("ea-php73", "___lsphp"))
	withInstalledPHPBins(t,
		"/opt/cpanel/ea-php73/root/usr/bin/php",
		"/opt/cpanel/ea-php80/root/usr/bin/php",
		"/opt/cpanel/ea-php81/root/usr/bin/php")

	if got, want := resolveDocrootPHPBin("alice", docroot), "/opt/cpanel/ea-php73/root/usr/bin/php"; got != want {
		t.Errorf("resolveDocrootPHPBin() = %q, want %q", got, want)
	}
}

// The walk must not leave the account: a directory above the owner's home is
// not the tenant's to configure.
func TestResolveDocrootPHPBinInheritStopsAtAccountHome(t *testing.T) {
	f := newInheritFixture(t, "alice")
	f.domainMap("example.com: alice==root==main==example.com==%HOME%/public_html==192.0.2.10:80==192.0.2.10:443====0==")
	docroot := f.dir("public_html")
	f.htaccess(filepath.Dir(f.home), cpanelHandlerBlock("ea-php73", "___lsphp"))
	withInstalledPHPBins(t, "/opt/cpanel/ea-php73/root/usr/bin/php")

	if got := resolveDocrootPHPBin("alice", docroot); got != "" {
		t.Errorf("handler above the account home resolved to %q, want empty", got)
	}
}

func TestResolveDocrootPHPBinInheritEmptyBlockKeepsAncestor(t *testing.T) {
	for name, body := range map[string]string{
		"empty":       "",
		"comment":     "# Inherit the PHP version from the parent directory.\n",
		"other types": "AddHandler application/x-httpd-ea-php73 .phtml .php7\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := newInheritFixture(t, "alice")
			f.domainMap("example.com: alice==root==main==example.com==%HOME%/public_html==192.0.2.10:80==192.0.2.10:443====0==inherit")
			docroot := f.dir("public_html/blog")
			f.htaccess(f.home, cpanelHandlerBlock("ea-php81", "___lsphp"))
			f.htaccess(docroot, cpanelHandlerBegin+"\n"+body+cpanelHandlerEnd+"\n")
			const want = "/opt/cpanel/ea-php81/root/usr/bin/php"
			withInstalledPHPBins(t, want)
			if got := resolveDocrootPHPBin("alice", docroot); got != want {
				t.Fatalf("block without a PHP mapping hid ancestor: got %q, want %q", got, want)
			}
		})
	}
}

func TestResolveDocrootPHPBinInheritRejectsSymlinkedDirectories(t *testing.T) {
	for _, targetHandler := range []bool{false, true} {
		t.Run(fmt.Sprintf("outside handler=%t", targetHandler), func(t *testing.T) {
			f := newInheritFixture(t, "alice")
			outside := filepath.Join(f.root, "outside")
			if err := os.MkdirAll(filepath.Join(outside, "blog"), 0o755); err != nil {
				t.Fatal(err)
			}
			if targetHandler {
				f.htaccess(filepath.Join(outside, "blog"), cpanelHandlerBlock("ea-php73", "___lsphp"))
			}
			f.htaccess(f.home, cpanelHandlerBlock("ea-php81", "___lsphp"))
			if err := os.Symlink(outside, filepath.Join(f.home, "public_html")); err != nil {
				t.Fatal(err)
			}
			f.domainMap("example.com: alice==root==main==example.com==%HOME%/public_html==192.0.2.10:80==192.0.2.10:443====0==inherit")
			withInstalledPHPBins(t,
				"/opt/cpanel/ea-php73/root/usr/bin/php",
				"/opt/cpanel/ea-php81/root/usr/bin/php")
			if got := resolveDocrootPHPBin("alice", filepath.Join(f.home, "public_html", "blog")); got != "" {
				t.Fatalf("symlinked ancestor resolved to %q, want no selection", got)
			}
		})
	}
}

func TestResolveDocrootPHPBinInheritRejectsUnusableDirectory(t *testing.T) {
	for _, kind := range []string{"missing", "dangling symlink", "fifo", "regular file", "home symlink"} {
		t.Run(kind, func(t *testing.T) {
			f := newInheritFixture(t, "alice")
			f.htaccess(f.home, cpanelHandlerBlock("ea-php81", ""))
			dir := filepath.Join(f.home, "public_html")
			var err error
			switch kind {
			case "dangling symlink":
				err = os.Symlink(filepath.Join(f.root, "absent"), dir)
			case "fifo":
				err = unix.Mkfifo(dir, 0o600)
			case "regular file":
				err = os.WriteFile(dir, nil, 0o600)
			case "home symlink":
				dir = f.dir("public_html")
				moved := f.home + "-moved"
				if err = os.Rename(f.home, moved); err == nil {
					err = os.Symlink(moved, f.home)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			f.domainMap("example.com: alice==root==main==example.com==%HOME%/public_html==192.0.2.10:80==192.0.2.10:443====0==inherit")
			withInstalledPHPBins(t, "/opt/cpanel/ea-php81/root/usr/bin/php")
			done := make(chan string, 1)
			go func() { done <- resolveDocrootPHPBin("alice", dir) }()
			select {
			case got := <-done:
				if got != "" {
					t.Fatalf("unusable directory selected %q", got)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("resolution blocked on a tenant directory")
			}
		})
	}
}

func TestCpanelHandlerVersionEmptyAndUnknownMappings(t *testing.T) {
	emptyBlock := cpanelHandlerBegin + "\n# Inherit\n" + cpanelHandlerEnd + "\n"
	unknownBlock := cpanelHandlerBegin + "\nAddHandler custom-php .php\n" + cpanelHandlerEnd + "\n"
	for _, tc := range []struct {
		name, content, version string
		found                  bool
	}{
		{"empty alone", emptyBlock, "", false},
		{"empty after version", cpanelHandlerBlock("ea-php73", "") + emptyBlock, "ea-php73", true},
		{"unknown after version", cpanelHandlerBlock("ea-php73", "") + unknownBlock, "", true},
		{"empty after unknown", unknownBlock + emptyBlock, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			version, found := cpanelHandlerVersion(tc.content)
			if version != tc.version || found != tc.found {
				t.Fatalf("got (%q, %t), want (%q, %t)", version, found, tc.version, tc.found)
			}
		})
	}
}

// The walk is bounded by the owner's passwd home. An owner with no passwd
// entry, or a docroot outside that home, has no boundary to walk within.
func TestResolveDocrootPHPBinInheritRequiresDocrootInsideOwnerHome(t *testing.T) {
	t.Run("owner missing from passwd", func(t *testing.T) {
		f := newInheritFixture(t, "alice")
		withMockPasswd(t, "bob:x:1002:1002::/home/bob:/bin/bash\n")
		f.domainMap("example.com: alice==root==main==example.com==%HOME%/public_html==192.0.2.10:80==192.0.2.10:443====0==")
		docroot := f.dir("public_html")
		f.htaccess(docroot, cpanelHandlerBlock("ea-php73", "___lsphp"))
		withInstalledPHPBins(t, "/opt/cpanel/ea-php73/root/usr/bin/php")

		if got := resolveDocrootPHPBin("alice", docroot); got != "" {
			t.Errorf("owner without a home resolved to %q, want empty", got)
		}
	})
	t.Run("docroot outside the owner's home", func(t *testing.T) {
		f := newInheritFixture(t, "alice")
		outside := filepath.Join(f.root, "srv", "alice", "public_html")
		if err := os.MkdirAll(outside, 0o755); err != nil {
			t.Fatal(err)
		}
		f.domainMap("example.com: alice==root==main==example.com==" + outside + "==192.0.2.10:80==192.0.2.10:443====0==")
		f.htaccess(outside, cpanelHandlerBlock("ea-php73", "___lsphp"))
		withInstalledPHPBins(t, "/opt/cpanel/ea-php73/root/usr/bin/php")

		if got := resolveDocrootPHPBin("alice", outside); got != "" {
			t.Errorf("docroot outside the home resolved to %q, want empty", got)
		}
	})
}

// Only the block cPanel writes is a version selection. A hand-written or
// commented handler, or one that does not cover .php, says nothing reliable.
func TestResolveDocrootPHPBinInheritIgnoresNonCPanelHandlers(t *testing.T) {
	for name, content := range map[string]string{
		"handler outside the block": "AddHandler application/x-httpd-ea-php73___lsphp .php .php7 .phtml\n",
		"commented handler in block": "# php -- BEGIN cPanel-generated handler, do not edit\n" +
			"# AddHandler application/x-httpd-ea-php73___lsphp .php .php7 .phtml\n" +
			"# php -- END cPanel-generated handler, do not edit\n",
		"handler not covering .php": "# php -- BEGIN cPanel-generated handler, do not edit\n" +
			"AddHandler application/x-httpd-ea-php73___lsphp .phtml .php7\n" +
			"# php -- END cPanel-generated handler, do not edit\n",
		"unterminated block": "# php -- BEGIN cPanel-generated handler, do not edit\n" +
			"AddHandler application/x-httpd-ea-php73___lsphp .php .php7 .phtml\n",
		"version-shaped junk": "# php -- BEGIN cPanel-generated handler, do not edit\n" +
			"AddHandler application/x-httpd-ea-php73;id .php\n" +
			"# php -- END cPanel-generated handler, do not edit\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := newInheritFixture(t, "alice")
			f.domainMap("example.com: alice==root==main==example.com==%HOME%/public_html==192.0.2.10:80==192.0.2.10:443====0==")
			docroot := f.dir("public_html")
			f.htaccess(docroot, content)
			withInstalledPHPBins(t, "/opt/cpanel/ea-php73/root/usr/bin/php")

			if got := resolveDocrootPHPBin("alice", docroot); got != "" {
				t.Errorf("resolveDocrootPHPBin() = %q, want empty", got)
			}
		})
	}
}

// A nearer .htaccess that cannot be read safely may override any ancestor
// handler, so the walk must stop rather than fall through to the parent. The
// tenant controls these files: a symlink must not be followed and a FIFO must
// not block the daemon.
func TestResolveDocrootPHPBinInheritUnjudgeableHtaccessStopsWalk(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plant func(t *testing.T, f *inheritFixture, docroot string)
	}{
		{"symlink", func(t *testing.T, f *inheritFixture, docroot string) {
			target := filepath.Join(f.root, "elsewhere.htaccess")
			if err := os.WriteFile(target, []byte(cpanelHandlerBlock("ea-php73", "___lsphp")), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(docroot, ".htaccess")); err != nil {
				t.Fatal(err)
			}
		}},
		{"fifo", func(t *testing.T, f *inheritFixture, docroot string) {
			if err := unix.Mkfifo(filepath.Join(docroot, ".htaccess"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory", func(t *testing.T, f *inheritFixture, docroot string) {
			if err := os.Mkdir(filepath.Join(docroot, ".htaccess"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized", func(t *testing.T, f *inheritFixture, docroot string) {
			body := cpanelHandlerBlock("ea-php73", "___lsphp") + strings.Repeat("#", htaccessMaxFileBytes)
			f.htaccess(docroot, body)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInheritFixture(t, "alice")
			f.domainMap("sub.example.com: alice==root==sub==example.com==%HOME%/public_html/sub==192.0.2.10:80==192.0.2.10:443====0==")
			f.htaccess(f.dir("public_html"), cpanelHandlerBlock("ea-php81", "___lsphp"))
			docroot := f.dir("public_html/sub")
			tc.plant(t, f, docroot)
			withInstalledPHPBins(t,
				"/opt/cpanel/ea-php73/root/usr/bin/php",
				"/opt/cpanel/ea-php81/root/usr/bin/php")

			done := make(chan string, 1)
			go func() { done <- resolveDocrootPHPBin("alice", docroot) }()
			select {
			case got := <-done:
				if got != "" {
					t.Errorf("resolveDocrootPHPBin() = %q, want empty", got)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("resolveDocrootPHPBin blocked on the tenant .htaccess")
			}
		})
	}
}

// A handler naming an interpreter that is not installed cannot run the cron;
// the caller falls back rather than installing a line that always fails.
func TestResolveDocrootPHPBinInheritRequiresInstalledInterpreter(t *testing.T) {
	f := newInheritFixture(t, "alice")
	f.domainMap("example.com: alice==root==main==example.com==%HOME%/public_html==192.0.2.10:80==192.0.2.10:443====0==")
	docroot := f.dir("public_html")
	f.htaccess(docroot, cpanelHandlerBlock("ea-php72", "___lsphp"))
	withInstalledPHPBins(t, "/opt/cpanel/ea-php73/root/usr/bin/php")

	if got := resolveDocrootPHPBin("alice", docroot); got != "" {
		t.Errorf("uninstalled handler interpreter resolved to %q, want empty", got)
	}
}

// Only an inheriting vhost consults the handler chain. An explicit version is
// cPanel's own selection, and a malformed or conflicting map stays unresolved
// whatever the tenant's files say.
func TestResolveDocrootPHPBinHandlerOnlyForInheritingVhost(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows []string
		want string
	}{
		{
			name: "explicit version wins",
			rows: []string{"example.com: alice==root==main==example.com==%HOME%/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74"},
			want: "/opt/cpanel/ea-php74/root/usr/bin/php",
		},
		{
			name: "malformed column",
			rows: []string{"example.com: alice==root==main==example.com==%HOME%/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php83; rm -rf /"},
		},
		{
			name: "explicit and inheriting rows share the docroot",
			rows: []string{
				"example.com: alice==root==main==example.com==%HOME%/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74",
				"alias.example.com: alice==root==addon==example.com==%HOME%/public_html==192.0.2.10:80==192.0.2.10:443====0==inherit",
			},
		},
		{
			name: "inheriting and malformed rows share the docroot",
			rows: []string{
				"example.com: alice==root==main==example.com==%HOME%/public_html==192.0.2.10:80==192.0.2.10:443====0==",
				"alias.example.com: alice==root==addon==example.com==%HOME%/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php8",
			},
		},
		{
			name: "no vhost serves the docroot",
			rows: []string{"other.example.com: alice==root==main==other.example.com==%HOME%/other==192.0.2.10:80==192.0.2.10:443====0=="},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInheritFixture(t, "alice")
			f.domainMap(tc.rows...)
			docroot := f.dir("public_html")
			f.htaccess(docroot, cpanelHandlerBlock("ea-php81", "___lsphp"))
			withInstalledPHPBins(t, "/opt/cpanel/ea-php81/root/usr/bin/php")

			if got := resolveDocrootPHPBin("alice", docroot); got != tc.want {
				t.Errorf("resolveDocrootPHPBin() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The line CSM actually installs must carry the inherited handler's PHP.
func TestInstallUserWPCronWritesInheritedHandlerPHP(t *testing.T) {
	f := newInheritFixture(t, "alice")
	f.domainMap("site.example.com: alice==root==addon==main.example.com==%HOME%/site.example.com==192.0.2.10:80==192.0.2.10:443====0==")
	docroot := f.dir("site.example.com")
	f.htaccess(docroot, cpanelHandlerBlock("ea-php73", "___lsphp"))
	withInstalledPHPBins(t, "/opt/cpanel/ea-php73/root/usr/bin/php")
	withLookPath(t, "/usr/local/bin/php")
	rec := &crontabRecorder{}
	withMockCmd(t, rec.mock())

	changed, err := installUserWPCron("alice", docroot, WPCronFixOptions{IntervalMinutes: 15})
	if err != nil {
		t.Fatalf("installUserWPCron: %v", err)
	}
	if !changed || rec.installCalls != 1 {
		t.Fatalf("expected one crontab install, changed=%v calls=%d", changed, rec.installCalls)
	}
	if !strings.Contains(rec.lastInstalled, "'/opt/cpanel/ea-php73/root/usr/bin/php'") {
		t.Errorf("installed crontab does not use the inherited handler PHP:\n%s", rec.lastInstalled)
	}
}

// Sites fixed by earlier releases already carry a line on the system-default
// wrapper; the startup migration is the only path that reaches them.
func TestMigrateWPCronCrontabsRewritesInheritedHandlerPHP(t *testing.T) {
	f := newInheritFixture(t, "alice")
	f.domainMap("site.example.com: alice==root==addon==main.example.com==%HOME%/site.example.com==192.0.2.10:80==192.0.2.10:443====0==")
	docroot := f.dir("site.example.com")
	f.htaccess(docroot, cpanelHandlerBlock("ea-php73", "___lsphp"))
	withInstalledPHPBins(t, "/opt/cpanel/ea-php73/root/usr/bin/php")

	spool := t.TempDir()
	withWPCronSpoolDirs(t, spool)
	managed := wpCronJobMarker + docroot + "\n" +
		wpCronJobLine("alice", docroot, WPCronFixOptions{IntervalMinutes: 15, PHPBin: "/usr/local/bin/php"}) + "\n"
	if err := os.WriteFile(filepath.Join(spool, "alice"), []byte(managed), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := &migrateCrontabMock{crontabs: map[string]string{"alice": managed}, installs: map[string]string{}}
	withMockCmd(t, rec.mock())
	cfg := wpCronMigrateConfig()
	cfg.Performance.WPCronFix.PHPBin = ""

	if got := MigrateWPCronCrontabs(cfg); got != 1 {
		t.Fatalf("migration pass = %d, want 1", got)
	}
	installed := rec.installs["alice"]
	if !strings.Contains(installed, "'/opt/cpanel/ea-php73/root/usr/bin/php'") || strings.Contains(installed, "'/usr/local/bin/php'") {
		t.Fatalf("migration did not move the line to the inherited handler PHP:\n%s", installed)
	}
}
