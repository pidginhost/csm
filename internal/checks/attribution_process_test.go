package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// A symlink into another account's home is attributed to the account that
// planted it, with the link path carried as the finding's file.
func TestSymlinkAttackStampsOwner(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	alice := filepath.Join(root, "alice")
	link := filepath.Join(alice, "public_html", "peek")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "bob", "secret"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "bob", "secret"), link); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanForMaliciousSymlinks(filepath.Join(alice, "public_html"), "alice", alice, 4, &findings)
	seen := expectAttributed(t, findings, "alice")
	requireChecks(t, seen, "symlink_attack")
	for _, f := range findings {
		if f.FilePath != link || f.TenantID != "alice" {
			t.Fatalf("symlink finding %+v, want FilePath %s and TenantID alice", f, link)
		}
	}
}

// writePasswdFixture writes a passwd file naming alice as a hosting account
// under root and nobody as a service user, and points the UID cache at it.
func writePasswdFixture(t *testing.T, root string) {
	t.Helper()
	passwd := filepath.Join(t.TempDir(), "passwd")
	body := "root:x:0:0:root:/root:/bin/bash\n" +
		"nobody:x:65534:65534:nobody:/var/lib/nobody:/usr/sbin/nologin\n" +
		"alice:x:1001:1001::" + filepath.Join(root, "alice") + ":/bin/bash\n" +
		"bob:x:1002:1002::" + filepath.Join(root, "bob") + ":/bin/bash\n"
	if err := os.WriteFile(passwd, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(swapDefaultUIDCacheForTest(passwd))
}

func TestHostingAccountForUser(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	writePasswdFixture(t, root)
	cases := map[string]string{"alice": "alice", "nobody": "", "root": "", "ghost": "", "unknown": "", "": "", "uid:1001": ""}
	for name, want := range cases {
		if got := HostingAccountForUser(name); got != want {
			t.Errorf("HostingAccountForUser(%q) = %q, want %q", name, got, want)
		}
	}
}

// Paste-site connections are attributed to the process owner only when that
// owner is a hosting account.
func TestExfiltrationFindingStampsOwner(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	writePasswdFixture(t, root)
	procs := map[string]struct{ uid, cmdline string }{
		"4242": {"1001", "curl\x00https://pastebin.com/raw/x\x00"},
		"4343": {"65534", "curl\x00https://pastebin.com/raw/y\x00"},
	}
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/proc/[0-9]*/cmdline" {
				return []string{"/proc/4242/cmdline", "/proc/4343/cmdline"}, nil
			}
			return nil, nil
		},
		readFile: func(path string) ([]byte, error) {
			pid := filepath.Base(filepath.Dir(path))
			p, ok := procs[pid]
			if !ok {
				return nil, os.ErrNotExist
			}
			switch filepath.Base(path) {
			case "status":
				return []byte("Name:\tcurl\nUid:\t" + p.uid + "\t" + p.uid + "\t" + p.uid + "\t" + p.uid + "\n"), nil
			case "cmdline":
				return []byte(p.cmdline), nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckOutboundPasteSites(context.Background(), &config.Config{}, nil)
	owners := map[string]int{}
	for _, f := range findings {
		if f.Check != "exfiltration_paste_site" {
			continue
		}
		owners[f.TenantID]++
		if got := extractAccountFromFinding(f); got != f.TenantID {
			t.Errorf("correlation account %q != TenantID %q", got, f.TenantID)
		}
	}
	if owners["alice"] != 1 || owners[""] != 1 || len(findings) != 2 {
		t.Fatalf("owners %v from %+v; want one alice row and one unattributed service-user row", owners, findings)
	}
}

// AF_ALG audit events resolve the audit uid through the shared passwd cache:
// a hosting account's uid stamps the owner, any other uid stays unattributed.
func TestAFALGFindingStampsOwner(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	writePasswdFixture(t, root)
	withMockCmd(t, grepStubReturning([]byte(
		`type=SYSCALL msg=audit(1.0:1): a0=38 auid=1001 uid=1001 comm="x" exe="/x" key="csm_af_alg_socket"
type=SYSCALL msg=audit(2.0:2): a0=38 auid=0 uid=0 comm="bad" exe="/tmp/bad" key="csm_af_alg_socket"
type=SYSCALL msg=audit(3.0:3): a0=38 auid=4242 uid=4242 comm="bad" exe="/tmp/bad" key="csm_af_alg_socket"`)))
	got := CheckAFAlgSocketUsage(context.Background(), &config.Config{}, newTestStore(t))
	if len(got) != 3 {
		t.Fatalf("findings %+v", got)
	}
	for i, want := range []string{"alice", "", ""} {
		if got[i].TenantID != want {
			t.Errorf("event %d: TenantID %q, want %q", i+1, got[i].TenantID, want)
		}
		if acct := extractAccountFromFinding(got[i]); acct != want {
			t.Errorf("event %d: correlation account %q, want %q", i+1, acct, want)
		}
	}
	res := CorrelateFindings(append([]alert.Finding{critical("db_rogue_admin", "bob"), critical("db_rogue_admin", "carol")}, got[0]))
	if len(res.Derived) != 1 || len(res.Unattributed) != 0 {
		t.Fatalf("attributed AF_ALG finding did not complete the aggregate: %+v", res)
	}
}

func TestHostingAccountForUserRequiresDirectHome(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	passwd := filepath.Join(t.TempDir(), "passwd")
	body := "alice:x:1001:1001::" + filepath.Join(root, "alice", "service") + ":/bin/sh\n"
	if err := os.WriteFile(passwd, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(swapDefaultUIDCacheForTest(passwd))
	if got := HostingAccountForUser("alice"); got != "" {
		t.Fatalf("nested service home attributed to %q", got)
	}
}

func TestHostingAccountLookupCachesMissingUsers(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	passwd := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(passwd, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(swapDefaultUIDCacheForTest(passwd))
	if got := HostingAccountForUser("alice"); got != "" {
		t.Fatalf("missing user = %q", got)
	}
	body := "alice:x:1001:1001::" + filepath.Join(root, "alice") + ":/bin/sh\n"
	if err := os.WriteFile(passwd, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := HostingAccountForUser("alice"); got != "" {
		t.Errorf("missing user was re-read before refresh: %q", got)
	}
	defaultUIDCache.lastHomeRead = time.Now().Add(-uidCacheMissTTL)
	if got := HostingAccountForUser("alice"); got != "alice" {
		t.Fatalf("new account did not resolve after miss expiry: %q", got)
	}
	defaultUIDCache.Refresh()
	if got := HostingAccountForUser("alice"); got != "alice" {
		t.Fatalf("refreshed owner = %q", got)
	}
}

func TestSystemSymlinkAttackCarriesSourceOwner(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	home := filepath.Join(root, "alice")
	dir := filepath.Join(home, "public_html")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "peek")
	if err := os.Symlink("/etc/shadow", link); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanForMaliciousSymlinks(dir, "alice", home, 4, &findings)
	if len(findings) != 1 || findings[0].Check != "symlink_attack" || findings[0].Severity != alert.Critical {
		t.Fatalf("findings = %+v", findings)
	}
	if findings[0].FilePath != link || findings[0].TenantID != "alice" {
		t.Fatalf("missing source identity: %+v", findings[0])
	}
}
