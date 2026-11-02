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
	// A home carrying a newline and tabs tries to pass as ghost's record.
	const alice = "/srv/vmail/example.com/alice"
	for _, home := range []string{
		alice + "\t\t\tmaildir:" + alice + "/Maildir\nghost@example.com\t1000\t1000\t" + alice,
		alice + "\t\t\tmaildir:~/Maildir\talice@example.com\nghost@example.com\t1000\t1000\t" + alice,
		alice + "\t\t\tmaildir:~/Maildir\talice@example.com\nghost@example.com\t1000\t1000\t" + alice + "\t\t\tmaildir:~/Maildir\tghost@example.com\n" + alice,
	} {
		f.Add([]byte("alice@example.com\t1000\t1000\t"+home+"\t\t\tmaildir:~/Maildir\talice@example.com\n\n\n"), "alice@example.com\nghost@example.com")
	}
	// A %u renamed to hold tabs, with a newline in another field.
	for _, out := range []string{forged, forgedPlugins} {
		f.Add([]byte(out+"\n\n"), attacker+"\nghost@example.com\nzed@example.com")
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
			recs, err := parseDetails(out, batch, nloc)
			if err != nil {
				continue
			}
			seen := map[string]bool{}
			for _, r := range recs {
				if !slices.Contains(batch, r.name) || seen[r.name] || len(r.locs) != 1+nloc || r.uid < 0 || r.uid > math.MaxUint32 || r.gid < 0 || r.gid > math.MaxUint32 ||
					strings.ContainsFunc(r.home+r.mail+r.plugins+strings.Join(r.locs, ""), control) {
					t.Fatalf("record %+v of %q", r, batch)
				}
				seen[r.name] = true
			}
			// Accepted as a whole lookup: one line per user, nothing else.
			if _, err := inOrder(recs, batch); err == nil && len(slices.DeleteFunc(strings.Split(string(out), "\n"), func(l string) bool { return l == "" })) != len(batch) {
				t.Fatalf("lookup of %q accepted from %q", batch, out)
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
		_ = c.iterable()
		d := detail{uid: 1000, gid: 1000, home: "/home/u", locs: locs}
		paths := c.paths(d)
		for _, p := range paths {
			if filepath.Clean(p) != p || !filepath.IsAbs(p) {
				t.Fatalf("mail path %q", p)
			}
		}
		// Every Junk folder is a direct child of its Maildir++ root, which
		// is one of the paths the shared-path check compares.
		m, reason := c.mailbox("u@example.com", "example.com", d)
		if reason != "" {
			return
		}
		for _, p := range m.Junk {
			dir, base := filepath.Split(p)
			if filepath.Clean(p) != p || !filepath.IsAbs(p) || !strings.HasPrefix(base, ".") || base == "." || base == ".." ||
				slices.Contains(strings.Split(dir, "/"), "..") {
				t.Fatalf("junk path %q", p)
			}
			if !slices.Contains(paths, filepath.Dir(p)) {
				t.Fatalf("junk path %q outside mail paths %q", p, paths)
			}
		}
	})
}
