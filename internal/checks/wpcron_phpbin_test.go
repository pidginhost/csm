package checks

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// userdataFS serves only /etc/userdatadomains; every other read is a miss.
func userdataFS(content string) *mockOS {
	return &mockOS{readFile: func(name string) ([]byte, error) {
		if name == userdataDomainsPath {
			return []byte(content), nil
		}
		return nil, os.ErrNotExist
	}}
}

func withLookPath(t *testing.T, path string) {
	t.Helper()
	old := cmdExec
	SetCmdRunner(&mockCmd{lookPath: func(name string) (string, error) {
		if name == "php" && path != "" {
			return path, nil
		}
		return "", fmt.Errorf("not found")
	}})
	t.Cleanup(func() { SetCmdRunner(old) })
}

func TestParseVhostPHPVersionUsesOnlyVersionColumn(t *testing.T) {
	tests := []struct {
		name   string
		fields []string
		want   string
	}{
		{
			name:   "fixed PHP-version column",
			fields: strings.Split("alice==root==main==example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php83", "=="),
			want:   "ea-php83",
		},
		{
			name:   "fixed column with trailing empties",
			fields: strings.Split("alice==root==main==example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==alt-php81====", "=="),
			want:   "alt-php81",
		},
		{
			name:   "short legacy row with version-shaped final field",
			fields: strings.Split("alice==root==main==example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====ea-php74", "=="),
		},
		{
			name:   "version-shaped non-version column",
			fields: strings.Split("alice==root==main==example.com==/home/alice/public_html==ea-php74==192.0.2.10:443====0==", "=="),
		},
		{
			name:   "version-shaped field after empty version column",
			fields: strings.Split("alice==root==main==example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0====ea-php74", "=="),
		},
		{
			name:   "nonempty field after version column",
			fields: strings.Split("alice==root==main==example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74==unexpected", "=="),
		},
		{
			name:   "delimiter in attacker-adjacent docroot",
			fields: strings.Split("alice==root==main==example.com==/home/alice/public_html==one==two==three==four==ea-php74==192.0.2.10:80==192.0.2.10:443====0==ea-php83", "=="),
		},
		{
			name:   "version-shaped domain and docroot",
			fields: strings.Split("alice==root==main==ea-php82==/home/alice/ea-php83==192.0.2.10:80==192.0.2.10:443====0==", "=="),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseVhostPHPVersion(tt.fields); got != tt.want {
				t.Errorf("parseVhostPHPVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPHPBinForVersionRejectsUnsupportedTokenWidths(t *testing.T) {
	for _, version := range []string{"ea-php8", "ea-php810", "alt-php8", "alt-php810"} {
		if got := phpBinForVersion(version); got != "" {
			t.Errorf("phpBinForVersion(%q) = %q, want empty", version, got)
		}
	}
}

// The managed WP-Cron line used to hardcode the system-default interpreter, so
// a docroot pinned to an older MultiPHP version ran wp-cron.php under the wrong
// PHP and fatal-errored every interval. The vhost's own version must win.
func TestResolveDocrootPHPBinUsesVhostVersion(t *testing.T) {
	withMockOS(t, userdataFS(strings.Join([]string{
		"old.example.com: alice==root==main==old.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74",
		"new.example.net: bob==root==main==new.example.net==/home/bob/public_html==192.0.2.11:80==192.0.2.11:443====0==ea-php83",
		"alt.example.org: carol==root==main==alt.example.org==/home/carol/public_html==192.0.2.12:80==192.0.2.12:443====0==alt-php81",
	}, "\n")))

	cases := []struct{ owner, docroot, want string }{
		{"alice", "/home/alice/public_html", "/opt/cpanel/ea-php74/root/usr/bin/php"},
		{"bob", "/home/bob/public_html", "/opt/cpanel/ea-php83/root/usr/bin/php"},
		{"carol", "/home/carol/public_html", "/opt/alt/php81/usr/bin/php"},
		{"alice", "/home/alice/public_html/", "/opt/cpanel/ea-php74/root/usr/bin/php"},
	}
	for _, c := range cases {
		if got := resolveDocrootPHPBin(c.owner, c.docroot); got != c.want {
			t.Errorf("resolveDocrootPHPBin(%q) = %q, want %q", c.docroot, got, c.want)
		}
	}
}

// An unknown docroot must not guess a version. Returning empty lets the caller
// fall back to detection rather than pinning a wrong interpreter.
func TestResolveDocrootPHPBinUnknownDocrootReturnsEmpty(t *testing.T) {
	withMockOS(t, userdataFS(
		"known.example.com: alice==root==main==known.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php83\n"))

	if got := resolveDocrootPHPBin("mallory", "/home/mallory/public_html"); got != "" {
		t.Errorf("unknown docroot resolved to %q, want empty", got)
	}
}

func TestResolveDocrootPHPBinRejectsConflictingVhostVersions(t *testing.T) {
	withMockOS(t, userdataFS(strings.Join([]string{
		"one.example.com: alice==root==main==one.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74",
		"two.example.com: alice==root==addon==one.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php83",
	}, "\n")))

	if got := resolveDocrootPHPBin("alice", "/home/alice/public_html"); got != "" {
		t.Errorf("conflicting vhost versions resolved to %q, want empty", got)
	}
}

func TestResolveDocrootPHPBinRejectsPartiallyUnusableVhostVersions(t *testing.T) {
	withMockOS(t, userdataFS(strings.Join([]string{
		"one.example.com: alice==root==main==one.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74",
		"alias.example.com: alice==root==addon==one.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==inherit",
	}, "\n")))

	if got := resolveDocrootPHPBin("alice", "/home/alice/public_html"); got != "" {
		t.Errorf("partially unusable vhost versions resolved to %q, want empty", got)
	}
}

func TestResolveDocrootPHPBinAcceptsMatchingDuplicateVersions(t *testing.T) {
	withMockOS(t, userdataFS(strings.Join([]string{
		"one.example.com: alice==root==main==one.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74",
		"alias.example.com: alice==root==addon==one.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74",
	}, "\n")))

	want := "/opt/cpanel/ea-php74/root/usr/bin/php"
	if got := resolveDocrootPHPBin("alice", "/home/alice/public_html"); got != want {
		t.Errorf("matching vhost versions resolved to %q, want %q", got, want)
	}
}

func TestResolveDocrootPHPBinRequiresMatchingOwner(t *testing.T) {
	withMockOS(t, userdataFS(
		"alias.example.com: bob==root==addon==example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74\n"))

	if got := resolveDocrootPHPBin("alice", "/home/alice/public_html"); got != "" {
		t.Errorf("different account's vhost resolved to %q, want empty", got)
	}
}

// A row with no version column, or a token that is not a recognised
// ea-php/alt-php version, must not produce a binary path. Anything else would
// let a malformed map inject an arbitrary command into a crontab.
func TestResolveDocrootPHPBinRejectsMalformedVersions(t *testing.T) {
	withMockOS(t, userdataFS(strings.Join([]string{
		"none.example.com: alice==root==main==none.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==",
		"inherit.example.net: bob==root==main==inherit.example.net==/home/bob/public_html==192.0.2.11:80==192.0.2.11:443====0==inherit",
		"evil.example.org: carol==root==main==evil.example.org==/home/carol/public_html==192.0.2.12:80==192.0.2.12:443====0==ea-php83; rm -rf /",
		"trav.example.io: dave==root==main==trav.example.io==/home/dave/public_html==192.0.2.13:80==192.0.2.13:443====0==../../bin/sh",
		"short.example.dev: erin==root==main==short.example.dev==/home/erin/public_html==192.0.2.14:80==192.0.2.14:443====0==ea-php8",
		"long.example.dev: frank==root==main==long.example.dev==/home/frank/public_html==192.0.2.15:80==192.0.2.15:443====0==alt-php810",
	}, "\n")))

	for _, account := range []struct{ owner, docroot string }{
		{"alice", "/home/alice/public_html"},
		{"bob", "/home/bob/public_html"},
		{"carol", "/home/carol/public_html"},
		{"dave", "/home/dave/public_html"},
		{"erin", "/home/erin/public_html"},
		{"frank", "/home/frank/public_html"},
	} {
		if got := resolveDocrootPHPBin(account.owner, account.docroot); got != "" {
			t.Errorf("resolveDocrootPHPBin(%q) = %q, want empty for malformed version", account.docroot, got)
		}
	}
}

// Every path this resolver can emit must already be accepted by the managed
// crontab recognizer, otherwise CSM would flag its own cron line as a
// sensitive-file change on the next scan.
func TestResolveDocrootPHPBinOutputIsRecognizedAsManaged(t *testing.T) {
	withMockOS(t, userdataFS(strings.Join([]string{
		"a.example.com: alice==root==main==a.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php56",
		"b.example.com: bob==root==main==b.example.com==/home/bob/public_html==192.0.2.11:80==192.0.2.11:443====0==ea-php85",
		"c.example.com: carol==root==main==c.example.com==/home/carol/public_html==192.0.2.12:80==192.0.2.12:443====0==alt-php81",
	}, "\n")))

	for _, account := range []struct{ owner, docroot string }{
		{"alice", "/home/alice/public_html"},
		{"bob", "/home/bob/public_html"},
		{"carol", "/home/carol/public_html"},
	} {
		bin := resolveDocrootPHPBin(account.owner, account.docroot)
		if bin == "" {
			t.Fatalf("resolveDocrootPHPBin(%q) returned empty", account.docroot)
		}
		if !safeManagedWPCronPHPBin(bin) {
			t.Errorf("resolved %q is not accepted by safeManagedWPCronPHPBin", bin)
		}
		job := wpCronJobMarker + account.docroot + "\n" +
			wpCronJobLine(account.owner, account.docroot, WPCronFixOptions{PHPBin: bin}) + "\n"
		if !crontabIsExclusivelyCSMWPCron(account.owner, []byte(job)) {
			t.Errorf("resolved %q produced a cron line not recognized as CSM-managed", bin)
		}
	}
}

// The cron line itself must carry the per-vhost interpreter.
func TestWPCronJobLineUsesPerVhostPHP(t *testing.T) {
	withMockOS(t, userdataFS(
		"old.example.com: alice==root==main==old.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74\n"))

	line := wpCronJobLine("alice", "/home/alice/public_html", WPCronFixOptions{IntervalMinutes: 15})
	if !strings.Contains(line, "/opt/cpanel/ea-php74/root/usr/bin/php") {
		t.Errorf("cron line does not use the vhost PHP: %s", line)
	}
	if strings.Contains(line, "'/usr/local/bin/php'") {
		t.Errorf("cron line still pins the system default PHP: %s", line)
	}
}

// An operator who sets php_bin explicitly is overriding the resolver on
// purpose; that must keep winning over the per-vhost lookup.
func TestWPCronJobLineExplicitPHPBinOverridesVhost(t *testing.T) {
	withMockOS(t, userdataFS(
		"old.example.com: alice==root==main==old.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74\n"))

	line := wpCronJobLine("alice", "/home/alice/public_html",
		WPCronFixOptions{IntervalMinutes: 15, PHPBin: "/usr/local/bin/php"})
	if !strings.Contains(line, "'/usr/local/bin/php'") {
		t.Errorf("explicit PHPBin was not honoured: %s", line)
	}
	if strings.Contains(line, "ea-php74") {
		t.Errorf("explicit PHPBin was overridden by the vhost lookup: %s", line)
	}
}

// Regression: the install path used to default PHPBin to the detected
// interpreter before building the line, which silently bypassed the per-vhost
// lookup. Exercising installUserWPCron (not just the line builder) is what
// catches that -- the crontab actually written must carry the vhost's PHP.
func TestInstallUserWPCronWritesPerVhostPHP(t *testing.T) {
	withMockOS(t, userdataFS(
		"old.example.com: alice==root==main==old.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74\n"))
	withLookPath(t, "/usr/local/bin/php")

	rec := &crontabRecorder{}
	old := cmdExec
	SetCmdRunner(rec.mock())
	defer SetCmdRunner(old)

	changed, err := installUserWPCron("alice", "/home/alice/public_html",
		WPCronFixOptions{IntervalMinutes: 15})
	if err != nil {
		t.Fatalf("installUserWPCron: %v", err)
	}
	if !changed || rec.installCalls != 1 {
		t.Fatalf("expected one crontab install, changed=%v calls=%d", changed, rec.installCalls)
	}
	if !strings.Contains(rec.lastInstalled, "/opt/cpanel/ea-php74/root/usr/bin/php") {
		t.Errorf("installed crontab does not use the vhost PHP:\n%s", rec.lastInstalled)
	}
	if strings.Contains(rec.lastInstalled, "'/usr/local/bin/php'") {
		t.Errorf("installed crontab still pins the system default PHP:\n%s", rec.lastInstalled)
	}
}

func TestInstallUserWPCronResolvesPHPInsideAccountLock(t *testing.T) {
	readStarted := make(chan struct{}, 1)
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name != userdataDomainsPath {
			return nil, os.ErrNotExist
		}
		readStarted <- struct{}{}
		return []byte("old.example.com: alice==root==main==old.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74\n"), nil
	}})
	rec := &crontabRecorder{}
	withMockCmd(t, rec.mock())

	lock := wpCronCrontabLock("alice")
	lock.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := installUserWPCron("alice", "/home/alice/public_html",
			WPCronFixOptions{IntervalMinutes: 15})
		done <- err
	}()

	resolvedBeforeLock := false
	select {
	case <-readStarted:
		resolvedBeforeLock = true
	case <-time.After(100 * time.Millisecond):
	}
	lock.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("installUserWPCron: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("installUserWPCron did not finish after releasing account lock")
	}
	if resolvedBeforeLock {
		t.Fatal("PHP mapping was resolved before acquiring the account lock")
	}
}

// With no override and no usable map entry the line must still be installable,
// falling back to the detected interpreter rather than emitting an empty path.
func TestWPCronJobLineFallsBackWhenVhostUnknown(t *testing.T) {
	withMockOS(t, userdataFS(""))
	withLookPath(t, "/usr/bin/php")

	line := wpCronJobLine("alice", "/home/alice/public_html", WPCronFixOptions{IntervalMinutes: 15})
	if !strings.Contains(line, "'/usr/bin/php'") {
		t.Errorf("expected detected PHP fallback, got: %s", line)
	}
}

// A WordPress install in a subdirectory of a docroot is not its own vhost, so
// the domain map has no entry for it -- but cPanel still serves it under the
// parent vhost, and therefore under the parent's PHP version. Falling back to
// the system default there reintroduced the exact breakage this fix exists to
// prevent: on a live host 19 managed jobs ran under 8.4 while their parent
// vhost was pinned as low as ea-php56.
func TestResolveDocrootPHPBinInheritsFromParentVhost(t *testing.T) {
	withMockOS(t, userdataFS(strings.Join([]string{
		"old.example.com: alice==root==main==old.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74",
		"new.example.net: bob==root==main==new.example.net==/home/bob/public_html==192.0.2.11:80==192.0.2.11:443====0==ea-php83",
	}, "\n")))

	cases := []struct{ owner, docroot, want string }{
		{"alice", "/home/alice/public_html/blog", "/opt/cpanel/ea-php74/root/usr/bin/php"},
		{"alice", "/home/alice/public_html/old/wordpress", "/opt/cpanel/ea-php74/root/usr/bin/php"},
		{"bob", "/home/bob/public_html/shop", "/opt/cpanel/ea-php83/root/usr/bin/php"},
	}
	for _, c := range cases {
		if got := resolveDocrootPHPBin(c.owner, c.docroot); got != c.want {
			t.Errorf("resolveDocrootPHPBin(%q, %q) = %q, want %q", c.owner, c.docroot, got, c.want)
		}
	}
}

// An exact entry must always beat an ancestor, or a subdomain docroot nested
// under the main one would silently run the parent's PHP version.
func TestResolveDocrootPHPBinPrefersExactOverAncestor(t *testing.T) {
	withMockOS(t, userdataFS(strings.Join([]string{
		"main.example.com: alice==root==main==main.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74",
		"sub.example.com: alice==root==sub==main.example.com==/home/alice/public_html/sub==192.0.2.10:80==192.0.2.10:443====0==ea-php83",
	}, "\n")))

	if got := resolveDocrootPHPBin("alice", "/home/alice/public_html/sub"); got != "/opt/cpanel/ea-php83/root/usr/bin/php" {
		t.Errorf("exact entry did not win over ancestor: got %q", got)
	}
	// deeper path under the subdomain inherits the subdomain, not the main site
	if got := resolveDocrootPHPBin("alice", "/home/alice/public_html/sub/blog"); got != "/opt/cpanel/ea-php83/root/usr/bin/php" {
		t.Errorf("nearest ancestor did not win: got %q", got)
	}
}

// A more specific vhost that cannot provide an unambiguous PHP version must
// not be skipped in favor of a usable parent. That would silently run the site
// under an interpreter its own mapping did not select.
func TestResolveDocrootPHPBinRejectsUnusableNearestVhost(t *testing.T) {
	for _, childRows := range []string{
		"sub.example.com: alice==root==sub==main.example.com==/home/alice/public_html/sub==192.0.2.10:80==192.0.2.10:443====0==inherit",
		strings.Join([]string{
			"one.example.com: alice==root==sub==main.example.com==/home/alice/public_html/sub==192.0.2.10:80==192.0.2.10:443====0==ea-php82",
			"two.example.com: alice==root==addon==main.example.com==/home/alice/public_html/sub==192.0.2.10:80==192.0.2.10:443====0==ea-php83",
		}, "\n"),
	} {
		withMockOS(t, userdataFS(strings.Join([]string{
			"main.example.com: alice==root==main==main.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74",
			childRows,
		}, "\n")))

		if got := resolveDocrootPHPBin("alice", "/home/alice/public_html/sub/blog"); got != "" {
			t.Errorf("skipped unusable nearest vhost and resolved parent version %q", got)
		}
	}
}

// Inheritance must never cross an account boundary or climb out of the account
// home; a docroot belonging to another user says nothing about this one.
func TestResolveDocrootPHPBinDoesNotInheritAcrossAccounts(t *testing.T) {
	withMockOS(t, userdataFS(strings.Join([]string{
		"a.example.com: alice==root==main==a.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74",
		"home.example.com: root==root==main==home.example.com==/home==192.0.2.12:80==192.0.2.12:443====0==ea-php83",
	}, "\n")))

	// mallory has no vhost of her own; /home must not be treated as an ancestor
	if got := resolveDocrootPHPBin("mallory", "/home/mallory/public_html/blog"); got != "" {
		t.Errorf("inherited across accounts or from /home: got %q", got)
	}
	// owner mismatch against alice's docroot must not resolve either
	if got := resolveDocrootPHPBin("mallory", "/home/alice/public_html/blog"); got != "" {
		t.Errorf("inherited another account's version: got %q", got)
	}
}

func TestWPCronDocrootCoversRequiresSafePathBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, vhostRoot, docroot string
		want                     bool
	}{
		{"exact", "/home/alice/public_html", "/home/alice/public_html", true},
		{"subdirectory", "/home/alice/public_html", "/home/alice/public_html/blog", true},
		{"prefix sibling", "/home/alice/public_html", "/home/alice/public_html_old/blog", false},
		{"home ancestor", "/home", "/home/alice/public_html", false},
		{"root ancestor", "/", "/home/alice/public_html", false},
		{"exact home", "/home", "/home", false},
		{"exact root", "/", "/", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := wpCronDocrootCovers(tc.vhostRoot, tc.docroot); got != tc.want {
				t.Errorf("wpCronDocrootCovers(%q, %q) = %v, want %v", tc.vhostRoot, tc.docroot, got, tc.want)
			}
		})
	}
}
