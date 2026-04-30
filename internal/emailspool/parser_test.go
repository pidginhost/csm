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
