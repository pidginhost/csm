package emailspool

import "testing"

func TestExtractDomain_BareAddress(t *testing.T) {
	got := ExtractDomain("user@Example.COM")
	if got != "example.com" {
		t.Fatalf("want example.com, got %q", got)
	}
}

func TestExtractDomain_DisplayName(t *testing.T) {
	got := ExtractDomain(`"Display Name" <user@example.com>`)
	if got != "example.com" {
		t.Fatalf("want example.com, got %q", got)
	}
}

func TestExtractDomain_QuotedLocalPart(t *testing.T) {
	got := ExtractDomain(`"a@b"@example.com`)
	if got != "example.com" {
		t.Fatalf("want example.com, got %q", got)
	}
}

func TestExtractDomain_Empty(t *testing.T) {
	if ExtractDomain("") != "" {
		t.Fatal("empty input must return empty domain")
	}
}

func TestIsSubdomainOrEqual(t *testing.T) {
	cases := []struct {
		candidate, base string
		want            bool
	}{
		{"foo.com", "foo.com", true},
		{"FOO.com", "foo.com", true},
		{"mail.foo.com", "foo.com", true},
		{"deep.mail.foo.com", "foo.com", true},
		{"foo.com", "mail.foo.com", false},
		{"barfoo.com", "foo.com", false},
		{"", "foo.com", false},
		{"foo.com", "", false},
	}
	for _, c := range cases {
		if got := IsSubdomainOrEqual(c.candidate, c.base); got != c.want {
			t.Errorf("IsSubdomainOrEqual(%q,%q)=%v, want %v", c.candidate, c.base, got, c.want)
		}
	}
}
