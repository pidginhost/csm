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

func TestParseServingIPValidatesBindingsAndIPv6(t *testing.T) {
	tests := []struct {
		name   string
		http   string
		https  string
		wantIP string
	}{
		{name: "prefer https", http: "192.0.2.80:80", https: "192.0.2.43:443", wantIP: "192.0.2.43"},
		{name: "fallback from malformed https", http: "192.0.2.80:80", https: "origin.example:443", wantIP: "192.0.2.80"},
		{name: "bracketed IPv6", http: "192.0.2.80:80", https: "[2001:db8::43]:443", wantIP: "2001:db8::43"},
		{name: "unbracketed IPv6", https: "2001:db8::43:443", wantIP: "2001:db8::43"},
		{name: "wrong https port falls back", http: "192.0.2.80:80", https: "192.0.2.43:80", wantIP: "192.0.2.80"},
		{name: "hostnames rejected", http: "origin.example:80", https: "cdn.example:443"},
		{name: "non-serving addresses rejected", http: "127.0.0.1:80", https: "[::]:443"},
		{name: "broken brackets rejected", https: "[2001:db8::43:443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fields := make([]string, 7)
			fields[5], fields[6] = tc.http, tc.https
			if got := parseServingIP(fields); got != tc.wantIP {
				t.Fatalf("parseServingIP() = %q, want %q", got, tc.wantIP)
			}
		})
	}
}

func TestParseUserdataDomainsMarksMissingServingIPIncomplete(t *testing.T) {
	content := "example.com: alice==root==main==example.com==/home/alice/public_html==origin.example:80==bad:443"
	vhosts, complete := parseUserdataDomainsChecked(content)
	if complete {
		t.Fatal("invalid serving bindings must make the vhost map incomplete")
	}
	if len(vhosts) != 1 || vhosts[0].ip != "" {
		t.Fatalf("parsed vhosts = %+v, want one vhost without a probe target", vhosts)
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

func TestDedupVhostsPrefersUsableServingIP(t *testing.T) {
	docroot := "/home/alice/public_html"
	got := dedupVhostsByDocroot([]vhost{
		{domain: "example.com", user: "alice", typ: "main", docroot: docroot},
		{domain: "alias.example", user: "alice", typ: "parked", docroot: docroot, ip: "192.0.2.10"},
	})

	if len(got) != 1 || got[0].domain != "alias.example" {
		t.Fatalf("deduped vhosts = %+v, want the vhost with a usable serving IP", got)
	}
}

func TestRelURLPathAllowsLeadingDoubleDotFilename(t *testing.T) {
	docroot := filepath.Join("home", "alice", "public_html")
	path := filepath.Join(docroot, "..backup.sql")
	if got := relURLPath(docroot, path); got != "/..backup.sql" {
		t.Fatalf("relURLPath() = %q, want /..backup.sql", got)
	}
}
