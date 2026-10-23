package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// registryOS is the real filesystem with the cPanel account registry
// redirected into a test directory.
type registryOS struct {
	realOS
	users string
}

func (r registryOS) Stat(name string) (os.FileInfo, error) {
	if account, ok := strings.CutPrefix(name, "/var/cpanel/users/"); ok {
		return os.Stat(filepath.Join(r.users, account))
	}
	return r.realOS.Stat(name)
}

// withPartitionedAccounts builds <base>/home as the only configured account
// root, registers accounts, and returns base.
func withPartitionedAccounts(t *testing.T, passwd string, registered ...string) string {
	t.Helper()
	base := t.TempDir()
	users := filepath.Join(base, "users")
	for _, dir := range []string{filepath.Join(base, "home"), users} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, account := range registered {
		if err := os.WriteFile(filepath.Join(users, account), []byte("STARTDATE=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	withAccountHomeRoots(t, filepath.Join(base, "home"))
	withMockOS(t, registryOS{users: users})
	withMockPasswd(t, strings.ReplaceAll(passwd, "BASE", base))
	return base
}

// cPanel's HOMEMATCH places new accounts on any matching partition, so an
// account can live on /home2 while the configured root is /home. Joining the
// name to the root pointed every account-scoped check at a directory that
// does not exist, and the account scan reported the account as missing.
func TestAccountHomeDirFindsRegisteredAccountOnAnotherPartition(t *testing.T) {
	base := withPartitionedAccounts(t, "alice:x:1001:1001::BASE/home2/alice:/bin/bash\n", "alice")
	home := filepath.Join(base, "home2", "alice")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}

	if got := accountHomeDir("alice"); got != home {
		t.Fatalf("accountHomeDir(alice) = %q, want the passwd home %q", got, home)
	}
	entries, err := GetScanHomeDirs(ContextWithAccountScope(context.Background(), "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || scanHomeDirPath(entries[0]) != home {
		t.Fatalf("scoped scan homes = %v, want only %s", entries, home)
	}
}

// Only a registered account whose passwd home is a real directory named after
// it qualifies. Anything else keeps the old root join, so a non-account or a
// redirected home is never scanned in an account's name.
func TestAccountHomeDirIgnoresUnqualifiedPasswdHomes(t *testing.T) {
	passwd := strings.Join([]string{
		"unregistered:x:1001:1001::BASE/home2/unregistered:/bin/bash",
		"renamed:x:1002:1002::BASE/home2/other:/bin/bash",
		"linked:x:1003:1003::BASE/home2/linked:/bin/bash",
		"missing:x:1004:1004::BASE/home2/missing:/bin/bash",
		"relative:x:1005:1005::home2/relative:/bin/bash",
	}, "\n") + "\n"
	base := withPartitionedAccounts(t, passwd, "renamed", "linked", "missing", "relative")
	for _, dir := range []string{"unregistered", "other", "target"} {
		if err := os.MkdirAll(filepath.Join(base, "home2", dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(base, "home2", "target"), filepath.Join(base, "home2", "linked")); err != nil {
		t.Fatal(err)
	}

	for _, account := range []string{"unregistered", "renamed", "linked", "missing", "relative"} {
		want := filepath.Join(base, "home", account)
		if got := accountHomeDir(account); got != want {
			t.Errorf("accountHomeDir(%s) = %q, want the root join %q", account, got, want)
		}
	}
}
