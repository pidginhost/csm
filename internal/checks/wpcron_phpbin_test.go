package checks

import (
	"fmt"
	"os"
	"strings"
	"testing"
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

// The managed WP-Cron line used to hardcode the system-default interpreter, so
// a docroot pinned to an older MultiPHP version ran wp-cron.php under the wrong
// PHP and fatal-errored every interval. The vhost's own version must win.
func TestResolveDocrootPHPBinUsesVhostVersion(t *testing.T) {
	withMockOS(t, userdataFS(strings.Join([]string{
		"old.example.com: alice==root==main==old.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74",
		"new.example.net: bob==root==main==new.example.net==/home/bob/public_html==192.0.2.11:80==192.0.2.11:443====0==ea-php83",
		"alt.example.org: carol==root==main==alt.example.org==/home/carol/public_html==192.0.2.12:80==192.0.2.12:443====0==alt-php81",
	}, "\n")))

	cases := []struct{ docroot, want string }{
		{"/home/alice/public_html", "/opt/cpanel/ea-php74/root/usr/bin/php"},
		{"/home/bob/public_html", "/opt/cpanel/ea-php83/root/usr/bin/php"},
		{"/home/carol/public_html", "/opt/alt/php81/usr/bin/php"},
		{"/home/alice/public_html/", "/opt/cpanel/ea-php74/root/usr/bin/php"},
	}
	for _, c := range cases {
		if got := resolveDocrootPHPBin(c.docroot); got != c.want {
			t.Errorf("resolveDocrootPHPBin(%q) = %q, want %q", c.docroot, got, c.want)
		}
	}
}

// An unknown docroot must not guess a version. Returning empty lets the caller
// fall back to detection rather than pinning a wrong interpreter.
func TestResolveDocrootPHPBinUnknownDocrootReturnsEmpty(t *testing.T) {
	withMockOS(t, userdataFS(
		"known.example.com: alice==root==main==known.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php83\n"))

	if got := resolveDocrootPHPBin("/home/mallory/public_html"); got != "" {
		t.Errorf("unknown docroot resolved to %q, want empty", got)
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
	}, "\n")))

	for _, dr := range []string{
		"/home/alice/public_html",
		"/home/bob/public_html",
		"/home/carol/public_html",
		"/home/dave/public_html",
	} {
		if got := resolveDocrootPHPBin(dr); got != "" {
			t.Errorf("resolveDocrootPHPBin(%q) = %q, want empty for malformed version", dr, got)
		}
	}
}

// Every path this resolver can emit must already be accepted by the managed
// crontab recognizer, otherwise CSM would flag its own cron line as a
// sensitive-file change on the next scan.
func TestResolveDocrootPHPBinOutputIsRecognizedAsManaged(t *testing.T) {
	withMockOS(t, userdataFS(strings.Join([]string{
		"a.example.com: alice==root==main==a.example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==ea-php74",
		"b.example.com: bob==root==main==b.example.com==/home/bob/public_html==192.0.2.11:80==192.0.2.11:443====0==alt-php81",
	}, "\n")))

	for _, dr := range []string{"/home/alice/public_html", "/home/bob/public_html"} {
		bin := resolveDocrootPHPBin(dr)
		if bin == "" {
			t.Fatalf("resolveDocrootPHPBin(%q) returned empty", dr)
		}
		if !safeManagedWPCronPHPBin(bin) {
			t.Errorf("resolved %q is not accepted by safeManagedWPCronPHPBin", bin)
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
