package dovecot

import (
	"cmp"
	"math"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func FuzzParseDoveadmUser(f *testing.F) {
	for _, set := range []string{"maildir", "slash", "static"} {
		for _, r := range capture(f, set) {
			if len(r.Argv) > 4 && r.Argv[0] == "doveadm" && r.Argv[1] == "user" {
				f.Add([]byte(r.Stdout), strings.Join(r.Argv[5:], "\n"))
			}
			if slices.Equal(r.Argv, []string{"doveadm", "user", "*"}) {
				f.Add([]byte(r.Stdout), "alice@example.com")
			}
		}
	}
	f.Fuzz(func(t *testing.T, out []byte, users string) {
		if names, err := parseUsers(out); err == nil {
			if len(names) == 0 || len(names) > MaxMailboxes || !slices.IsSorted(names) {
				t.Fatalf("listing %q", names)
			}
			for _, n := range names {
				user, domain, ok := canonical(n)
				if n == "" || strings.Contains(n, "\n") {
					t.Fatalf("name %q", n)
				}
				// A name passed to doveadm can be neither a mask nor carry
				// separators of the detail record.
				if ok && (strings.ContainsAny(user, "*?\t\n /\\") || user != strings.ToLower(user) || domain != "" && !strings.HasSuffix(user, "@"+domain)) {
					t.Fatalf("canonical(%q) = %q, %q", n, user, domain)
				}
			}
		}
		batch := strings.Split(users, "\n")
		for nloc := range 3 {
			found, err := parseDetails(out, batch, nloc)
			if err != nil {
				continue
			}
			for name, d := range found {
				if !slices.Contains(batch, name) || len(d.locs) != 1+nloc || d.uid < 0 || d.uid > math.MaxUint32 || d.gid < 0 || d.gid > math.MaxUint32 {
					t.Fatalf("record %q: %+v", name, d)
				}
			}
		}
	})
}

func FuzzParseDoveconfNamespaces(f *testing.F) {
	for _, set := range []string{"maildir", "slash", "static"} {
		for _, r := range capture(f, set) {
			if r.Argv[0] == "doveconf" {
				f.Add([]byte(r.Stdout))
			}
		}
	}
	f.Add([]byte("namespace inbox {\n  separator = /\n  mailbox \"a/../b\" {\n    special_use = \\Junk\n  }\n}\n"))
	f.Fuzz(func(t *testing.T, out []byte) {
		c, err := parseConfig(out)
		if err != nil {
			return
		}
		for _, j := range c.junk {
			if j.loc < 0 || j.loc > len(c.locs) {
				t.Fatalf("junk %+v with %d locations", j, len(c.locs))
			}
		}
		locs := append([]string{cmp.Or(c.location, "maildir:~/Maildir")}, c.locs...)
		for _, loc := range locs {
			if root, _, reason := parseLocation(loc, "/home/u"); reason == "" && (!filepath.IsAbs(root) || filepath.Clean(root) != root) {
				t.Fatalf("location %q: root %q", loc, root)
			}
		}
		// Every Junk folder is a direct child of its Maildir++ root.
		m, reason := c.mailbox("u@example.com", "example.com", detail{uid: 1000, gid: 1000, home: "/home/u", locs: locs})
		if reason != "" {
			return
		}
		for _, p := range m.Junk {
			dir, base := filepath.Split(p)
			if filepath.Clean(p) != p || !filepath.IsAbs(p) || !strings.HasPrefix(base, ".") || base == "." || base == ".." ||
				slices.Contains(strings.Split(dir, "/"), "..") {
				t.Fatalf("junk path %q", p)
			}
		}
	})
}
