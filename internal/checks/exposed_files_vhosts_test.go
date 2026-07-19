package checks

import "testing"

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
malformed-no-fields.example.com: onlyuser
`

	got := parseUserdataDomains(content)

	if len(got) != 3 {
		t.Fatalf("expected 3 vhosts, got %d: %+v", len(got), got)
	}
	want := []vhost{
		{domain: "foodture.example.com", user: "alice", typ: "sub", docroot: "/home/alice/foodture.example.com"},
		{domain: "shop.example.net", user: "bob", typ: "addon", docroot: "/home/bob/public_html"},
		{domain: "example.org", user: "carol", typ: "main", docroot: "/home/carol/public_html"},
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
