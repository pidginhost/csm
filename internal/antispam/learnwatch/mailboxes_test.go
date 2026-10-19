//go:build linux

package learnwatch

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestValidDomainRules(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	// 63+1+63+1+63+1+61 = 253 bytes.
	d253 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("b", 61)
	for in, want := range map[string]bool{
		"example.com":       true,
		"Example.COM":       true,
		"a-b.example.net":   true,
		"xn--bcher-kva.com": true,
		d253:                true,
		d253 + "c":          false,
		label63 + ".com":    true,
		label63 + "a.com":   false,
		"-a.example.com":    false,
		"a-.example.com":    false,
		"a..example.com":    false,
		".example.com":      false,
		"example.com.":      false,
		"":                  false,
		"localhost":         false,
		"virtual":           false,
		"b\u00fccher.com":   false,
		"a_b.example.com":   false,
		"a b.example.com":   false,
		"../example.com":    false,
		"example.com/x":     false,
		"exa\x00mple.com":   false,
	} {
		if got := ValidDomain(in); got != want {
			t.Errorf("ValidDomain(%q) = %v", in, got)
		}
	}
}

func TestValidMailboxRules(t *testing.T) {
	for in, want := range map[string]bool{
		"user":                  true,
		"first.last":            true,
		"a+tag":                 true,
		"o'brien":               true,
		"x_y-z":                 true,
		strings.Repeat("a", 64): true,
		strings.Repeat("a", 65): false,
		".user":                 false,
		"user.":                 false,
		"a..b":                  false,
		"":                      false,
		".":                     false,
		"..":                    false,
		"a/b":                   false,
		"a\\b":                  false,
		"a b":                   false,
		"a\tb":                  false,
		"a\x01b":                false,
		"\"quoted\"":            false,
		"a\"b":                  false,
		"m\u00fcller":           false,
		"a@b":                   false,
		"a,b":                   false,
	} {
		if got := ValidMailbox(in); got != want {
			t.Errorf("ValidMailbox(%q) = %v", in, got)
		}
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	writeMsg(t, path, data)
}

func reasons(skips []Skip) map[string]int {
	out := map[string]int{}
	for _, s := range skips {
		out[s.Reason]++
	}
	return out
}

func TestMailboxesBoundsAndRejects(t *testing.T) {
	a, h := openTenant(t)
	writeFile(t, filepath.Join(a.Home, "etc/example.com/passwd"), []byte(
		"user:x:1001:1001::/home/tenant1/mail/example.com/user:/home/tenant1\n"+
			"../../x:x:1001:1001::/home/tenant1/mail/example.com/x:/home/tenant1\n"+
			"a\x00b:x:1001:1001::/x:/x\n"+
			"m\u00fcller:x:1001:1001::/x:/x\n"+
			"user:x:1001:1001::/dup:/dup\n"+
			"\n"+
			"second:x:1001:1001::/x:/x\n"))
	var huge bytes.Buffer
	for i := 0; huge.Len() <= MaxMailboxListBytes; i++ {
		fmt.Fprintf(&huge, "box%d:x:1001:1001::/home/tenant1/mail/example.net/box%d:/home/tenant1\n", i, i)
	}
	writeFile(t, filepath.Join(a.Home, "etc/example.net/passwd"), huge.Bytes())
	if err := os.MkdirAll(filepath.Join(a.Home, "etc/bad_domain!"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(a.Home, "etc/ftpquota"), []byte("0"))
	got, skips, err := h.Mailboxes()
	if err != nil {
		t.Fatal(err)
	}
	want := []Mailbox{{}, {Domain: "example.com", Box: "second"}, {Domain: "example.com", Box: "user"}}
	if !slices.Equal(got, want) {
		t.Fatalf("mailboxes %+v", got)
	}
	r := reasons(skips)
	if r[SkipUnsupportedName] != 4 || r[SkipMailboxListTooLarge] != 1 || len(skips) != 5 {
		t.Fatalf("skips %+v", skips)
	}
}

func TestParseMailboxPasswdLimit(t *testing.T) {
	var b bytes.Buffer
	for i := range 10001 {
		fmt.Fprintf(&b, "box%d:x:1:1::/x:/x\n", i)
	}
	names, skips := ParseMailboxPasswd(b.Bytes(), MaxMailboxes)
	if len(names) != MaxMailboxes || !slices.Equal(skips, []Skip{{Reason: SkipMailboxLimit}}) {
		t.Fatalf("%d names, skips %+v", len(names), skips)
	}
}

func TestMailboxesNeverFollowsVirtual(t *testing.T) {
	a, h := openTenant(t)
	writeFile(t, filepath.Join(a.Home, "etc/virtual/passwd"), []byte("user:x:1:1::/x:/x\n"))
	if err := os.MkdirAll(filepath.Join(a.Home, "mail/virtual/user/.spam/cur"), 0o700); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	writeFile(t, filepath.Join(other, "passwd"), []byte("victim:x:1:1::/x:/x\n"))
	if err := os.Symlink(other, filepath.Join(a.Home, "etc/example.org")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(a.Home, "etc/example.com/passwd.real"), []byte("victim:x:1:1::/x:/x\n"))
	if err := os.Symlink("passwd.real", filepath.Join(a.Home, "etc/example.com/passwd")); err != nil {
		t.Fatal(err)
	}
	got, skips, err := h.Mailboxes()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []Mailbox{{}}) {
		t.Fatalf("mailboxes %+v", got)
	}
	if r := reasons(skips); r[SkipUnsupportedName] != 1 || r[SkipUnsafePath] != 2 {
		t.Fatalf("skips %+v", skips)
	}
}

func TestMailboxesWithoutEtc(t *testing.T) {
	_, h := openTenant(t)
	got, skips, err := h.Mailboxes()
	if err != nil || !slices.Equal(got, []Mailbox{{}}) || len(skips) != 0 {
		t.Fatalf("mailboxes %+v, skips %+v, error %v", got, skips, err)
	}
}
