package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCpanelUserDomains_ReadsAllDomainKinds(t *testing.T) {
	root := t.TempDir()
	user := "exampleuser"
	dir := filepath.Join(root, user)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := `main_domain: example.com
addon_domains:
  add1.example.net: add1.example.net
  add2.example.org: add2.example.org
parked_domains:
  - parked.example
sub_domains:
  - sub.example.com
`
	if err := os.WriteFile(filepath.Join(dir, "main"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	r := newUserDomainsResolverWithRoot(root, time.Minute)
	got, err := r.Domains(user)
	if err != nil {
		t.Fatalf("Domains: %v", err)
	}
	for _, want := range []string{"example.com", "add1.example.net", "add2.example.org", "parked.example", "sub.example.com"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %q in domain set: %+v", want, got)
		}
	}
}

func TestCpanelUserDomains_MissingUserReturnsErrEmptySet(t *testing.T) {
	r := newUserDomainsResolverWithRoot(t.TempDir(), time.Minute)
	got, err := r.Domains("nope")
	if err == nil {
		t.Fatal("expected error for missing user")
	}
	if len(got) != 0 {
		t.Errorf("expected empty set, got %+v", got)
	}
}

func TestCpanelUserDomains_TTLRefresh(t *testing.T) {
	root := t.TempDir()
	user := "u"
	dir := filepath.Join(root, user)
	_ = os.MkdirAll(dir, 0o755)
	write := func(domain string) {
		_ = os.WriteFile(filepath.Join(dir, "main"), []byte("main_domain: "+domain+"\n"), 0o644)
	}

	write("first.example")
	r := newUserDomainsResolverWithRoot(root, 50*time.Millisecond)
	got1, _ := r.Domains(user)
	if _, ok := got1["first.example"]; !ok {
		t.Fatal("missing first.example")
	}

	write("second.example")
	time.Sleep(80 * time.Millisecond)
	got2, _ := r.Domains(user)
	if _, ok := got2["second.example"]; !ok {
		t.Errorf("expected refreshed second.example, got %+v", got2)
	}
}
