package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestSystemdPathQuoting(t *testing.T) {
	path := "/srv/accounts/a %n \"quoted\""
	if got, want := quoteSystemdPath(path), `"/srv/accounts/a %%n \"quoted\""`; got != want {
		t.Fatalf("quoted=%q want=%q", got, want)
	}
	if servicePathWithin("/srv/accounts-other", "/srv/accounts") {
		t.Fatal("sibling matched write grant")
	}
}

func TestTrustedServiceGrantUsesRootControlledAncestor(t *testing.T) {
	root, resolveErr := filepath.EvalSymlinks(t.TempDir())
	if resolveErr != nil {
		t.Fatal(resolveErr)
	}
	user := filepath.Join(root, "alice")
	content := filepath.Join(user, "public")
	if err := os.MkdirAll(content, 0755); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if grant, err := trustedServiceGrant(content); err == nil {
			info, statErr := os.Stat(grant)
			if statErr != nil || info.Sys().(*syscall.Stat_t).Uid != 0 || grant == content {
				t.Fatalf("accepted user-controlled path as grant: %s, error=%v", grant, statErr)
			}
		}
		return
	}
	if err := os.Chown(user, 1001, 1002); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(content, 1001, 1002); err != nil {
		t.Fatal(err)
	}
	grant, err := trustedServiceGrant(content)
	if err != nil || grant != root {
		t.Fatalf("grant=%s error=%v, want=%s", grant, err, root)
	}
	link := filepath.Join(root, "alias")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedServiceGrant(link); err == nil {
		t.Fatal("accepted symlink grant")
	}
	for _, path := range []string{"/", "/etc", "/srv", "/var", "/tmp"} {
		if _, err := trustedServiceGrant(path); err == nil {
			t.Errorf("accepted broad grant %s", path)
		}
	}
	if strings.Contains(grant, "alice") {
		t.Fatal("tenant-controlled directory became a service grant")
	}
	unit, renderErr := systemdAccountRootsDropIn(&config.Config{AccountRoots: []string{content, content}})
	if renderErr != nil {
		t.Fatal(renderErr)
	}
	for _, directive := range []string{"ReadWritePaths=", "RequiresMountsFor="} {
		if count := strings.Count(unit, directive+quoteSystemdPath(root)+"\n"); count != 1 {
			t.Fatalf("root grant occurs %d times for %s: %s", count, directive, unit)
		}
		if strings.Contains(unit, directive+"\n") || strings.Contains(unit, quoteSystemdPath(content)) {
			t.Fatalf("unit resets existing grants or trusts a tenant path: %s", unit)
		}
	}
}
