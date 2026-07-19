package checks

import (
	"path/filepath"
	"testing"
)

// parseUserdataDomains turns /etc/userdatadomains into (domain, user, docroot,
// type) tuples. This is the only source that maps every vhost -- including
// addon and subdomain docroots that the public_html glob misses -- to a domain
// usable as the reachability-probe Host.
func TestParseUserdataDomains(t *testing.T) {
	content := `foodture.example.com: alice==root==sub==example.com==/home/alice/foodture.example.com==192.0.2.10:80==192.0.2.10:443====0==
shop.example.net: bob==root==addon==example.net==/home/bob/public_html==192.0.2.11:80==192.0.2.11:443====0==ea-php83
example.org: carol==root==main==example.org==/home/carol/public_html==192.0.2.12:80==192.0.2.12:443====0==

# a comment line
*: nobody==root================
*.wild.example.com: alice==root==sub==example.com==/home/alice/public_html==192.0.2.10:80==192.0.2.10:443====0==
malformed-no-fields.example.com: onlyuser
`

	got := parseUserdataDomains(content)

	if len(got) != 3 {
		t.Fatalf("expected 3 vhosts, got %d: %+v", len(got), got)
	}
	want := []vhost{
		{domain: "foodture.example.com", user: "alice", typ: "sub", docroot: "/home/alice/foodture.example.com", ip: "192.0.2.10"},
		{domain: "shop.example.net", user: "bob", typ: "addon", docroot: "/home/bob/public_html", ip: "192.0.2.11"},
		{domain: "example.org", user: "carol", typ: "main", docroot: "/home/carol/public_html", ip: "192.0.2.12"},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("vhost[%d] = %+v, want %+v", i, got[i], w)
		}
	}
}

func TestParseUserdataDomainsEmpty(t *testing.T) {
	if v := parseUserdataDomains(""); len(v) != 0 {
		t.Errorf("empty content should yield no vhosts, got %+v", v)
	}
}

func TestParseUserdataDomainsReportsMalformedInput(t *testing.T) {
	content := `example.com: alice==root==main==example.com==/home/alice/public_html
truncated.example: alice
localhost:8080: alice==root==main==example.com==/home/alice/public_html
relative.example: alice==root==addon==example.com==public_html
root.example: root==root==main==root.example==/
`
	vhosts, complete := parseUserdataDomainsChecked(content)
	if complete {
		t.Fatal("truncated vhost map must mark the exposed-files scan incomplete")
	}
	if len(vhosts) != 1 || vhosts[0].domain != "example.com" {
		t.Fatalf("valid vhosts = %+v, want example.com", vhosts)
	}
}

func TestDedupVhostsPrefersNonParkedProbeHost(t *testing.T) {
	docroot := "/home/alice/public_html"
	got := dedupVhostsByDocroot([]vhost{
		{domain: "redirect.example", user: "alice", typ: "parked", docroot: docroot + string(filepath.Separator)},
		{domain: "example.com", user: "alice", typ: "main", docroot: docroot},
		{domain: "shop.example.com", user: "alice", typ: "addon", docroot: docroot},
	})

	if len(got) != 1 {
		t.Fatalf("deduped vhosts = %+v, want one entry", got)
	}
	if got[0].domain != "example.com" {
		t.Fatalf("probe domain = %q, want non-parked main domain", got[0].domain)
	}
}

func TestRelURLPathAllowsLeadingDoubleDotFilename(t *testing.T) {
	docroot := filepath.Join("home", "alice", "public_html")
	path := filepath.Join(docroot, "..backup.sql")
	if got := relURLPath(docroot, path); got != "/..backup.sql" {
		t.Fatalf("relURLPath() = %q, want /..backup.sql", got)
	}
}
