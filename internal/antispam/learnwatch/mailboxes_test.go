//go:build linux

package learnwatch

import (
	"bytes"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestMailboxReadBudgetIncludesGrowingLists(t *testing.T) {
	remaining, bytesLeft := MaxMailboxes, int64(MaxAccountMailboxListBytes)
	for attempt := 0; bytesLeft > 0 && attempt < 5; attempt++ {
		// The tenant can grow the file after its size check. A rejected
		// oversized list must still consume the account's read budget.
		r := bytes.NewReader(bytes.Repeat([]byte{'x'}, MaxMailboxListBytes+1))
		before := bytesLeft
		_, skips, err := readMailboxData(r, &remaining, &bytesLeft)
		if err != nil {
			t.Fatal(err)
		}
		consumed := int64(r.Size()) - int64(r.Len())
		if before-bytesLeft != consumed {
			t.Fatalf("read %d bytes but charged %d", consumed, before-bytesLeft)
		}
		if bytesLeft <= 0 && !slices.Contains(skips, Skip{Reason: SkipMailboxLimit}) {
			t.Fatalf("exhausted budget did not stop account traversal: %+v", skips)
		}
	}
	if bytesLeft > 0 {
		t.Fatalf("rejected lists left %d bytes of budget", bytesLeft)
	}
}

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

func TestParseMailboxPasswdBoundsRecords(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		limit      int
		want       []string
		skips      []Skip
	}{
		{"duplicates", "a:x\na:x\nb:x\n", 2, []string{"a"}, []Skip{{Reason: SkipMailboxLimit}}},
		{"invalid", "../x:x\n../x:x\nb:x\n", 2, nil, []Skip{{Reason: SkipUnsupportedName}, {Reason: SkipUnsupportedName}, {Reason: SkipMailboxLimit}}},
		{"zero", "../x:x\na:x\n", 0, nil, []Skip{{Reason: SkipMailboxLimit}}},
		{"negative", "../x:x\na:x\n", -1, nil, []Skip{{Reason: SkipMailboxLimit}}},
		{"exact", "b:x\na:x\n", 2, []string{"a", "b"}, nil},
		{"exact duplicates", "a:x\na:x\n", 2, []string{"a"}, nil},
		// Empty lines cost a record too, so newlines cannot buy unbounded
		// parsing; one trailing newline ends the file without a record.
		{"empty lines", "\na:x\n\n", 3, []string{"a"}, nil},
		{"empty lines exhaust", "\na:x\n\n", 1, nil, []Skip{{Reason: SkipMailboxLimit}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, skips := ParseMailboxPasswd([]byte(tc.data), tc.limit)
			if !slices.Equal(got, tc.want) || !slices.Equal(skips, tc.skips) {
				t.Fatalf("names %v, skips %+v; want %v, %+v", got, skips, tc.want, tc.skips)
			}
		})
	}
}

func TestParseMailboxPasswdRequiresSeparator(t *testing.T) {
	got, skips := ParseMailboxPasswd([]byte("truncated\nuser:x:1:1::/x:/x\n"), 10)
	if !slices.Equal(got, []string{"user"}) || !slices.Equal(skips, []Skip{{Reason: SkipUnsupportedName}}) {
		t.Fatalf("names %v, skips %+v", got, skips)
	}
}

func TestMailboxesBoundsAccountRecords(t *testing.T) {
	for _, kind := range []string{"valid", "invalid", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			a, h := openTenant(t)
			want := []Mailbox{{}}
			for domainIndex, domain := range []string{"a.example.com", "b.example.com"} {
				var data bytes.Buffer
				for i := range MaxMailboxes/2 + 1 {
					name := fmt.Sprintf("box%05d", i)
					switch kind {
					case "invalid":
						name = "../x"
					case "duplicate":
						name = "user"
					}
					fmt.Fprintf(&data, "%s:x\n", name)
					if domainIndex*(MaxMailboxes/2+1)+i < MaxMailboxes && (kind == "valid" || kind == "duplicate" && i == 0) {
						want = append(want, Mailbox{Domain: domain, Box: name})
					}
				}
				writeFile(t, filepath.Join(a.Home, "etc", domain, "passwd"), data.Bytes())
			}
			got, skips, err := h.Mailboxes()
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, want) {
				t.Fatalf("mailboxes differ: got %d, want %d", len(got), len(want))
			}
			wantReasons := map[string]int{SkipMailboxLimit: 1}
			if kind == "invalid" {
				wantReasons[SkipUnsupportedName] = MaxMailboxes
			}
			if r := reasons(skips); !maps.Equal(r, wantReasons) {
				t.Fatalf("skip counts %v; want %v", r, wantReasons)
			}
		})
	}
}

func TestMailboxesAccountLimitBoundary(t *testing.T) {
	for _, tc := range []struct {
		name       string
		extra      bool
		nextDomain bool
	}{
		{"exact", false, false},
		{"next domain", false, true},
		{"overflow and next domain", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, h := openTenant(t)
			var data bytes.Buffer
			for range MaxMailboxes {
				data.WriteString("user:x\n")
			}
			if tc.extra {
				data.WriteString("extra:x\n")
			}
			writeFile(t, filepath.Join(a.Home, "etc/a.example.com/passwd"), data.Bytes())
			if tc.nextDomain {
				writeFile(t, filepath.Join(a.Home, "etc/b.example.com/passwd"), []byte("other:x\n"))
			}
			got, skips, err := h.Mailboxes()
			want := []Mailbox{{}, {Domain: "a.example.com", Box: "user"}}
			var wantSkips []Skip
			if tc.nextDomain || tc.extra {
				wantSkips = []Skip{{Reason: SkipMailboxLimit}}
			}
			if err != nil || !slices.Equal(got, want) || !slices.Equal(skips, wantSkips) {
				t.Fatalf("mailboxes %+v, skips %+v, error %v", got, skips, err)
			}
		})
	}
}

func TestMailboxesSkipsNonRegularLists(t *testing.T) {
	a, h := openTenant(t)
	// The short socket domain leaves room for the test's temporary path.
	for _, domain := range []string{"directory.example.com", "fifo.example.com", "sock.test"} {
		if err := os.MkdirAll(filepath.Join(a.Home, "etc", domain), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(a.Home, "etc/directory.example.com/passwd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(a.Home, "etc/fifo.example.com/passwd"), 0o600); err != nil {
		t.Fatal(err)
	}
	socket, err := net.Listen("unix", filepath.Join(a.Home, "etc/sock.test/passwd"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	writeFile(t, filepath.Join(a.Home, "etc/valid.example.com/passwd"), []byte("user:x\n"))
	got, skips, err := h.Mailboxes()
	want := []Mailbox{{}, {Domain: "valid.example.com", Box: "user"}}
	if err != nil || !slices.Equal(got, want) || len(skips) != 3 || reasons(skips)[SkipUnsafePath] != 3 {
		t.Fatalf("mailboxes %+v, skips %+v, error %v", got, skips, err)
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
	// The linked passwd is unsafe; the ~/etc/example.org link is no domain.
	if r := reasons(skips); r[SkipUnsupportedName] != 1 || r[SkipUnsafePath] != 1 || len(skips) != 2 {
		t.Fatalf("skips %+v", skips)
	}
}

// cPanel keeps non-domain links in ~/etc, such as the Roundcube database
// link; some homes also hold copied system links. None is a mail domain.
func TestMailboxesIgnoresEtcSymlinks(t *testing.T) {
	a, h := openTenant(t)
	writeFile(t, filepath.Join(a.Home, "etc/tenant.rcube.db.1700000000"), nil)
	if err := os.Symlink("tenant.rcube.db.1700000000", filepath.Join(a.Home, "etc/tenant.rcube.db.latest")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(a.Home, "etc/rc.d/rc0.d/passwd"), []byte("victim:x\n"))
	if err := os.Symlink("rc.d/rc0.d", filepath.Join(a.Home, "etc/rc0.d")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(a.Home, "etc/example.com/passwd"), []byte("user:x\n"))
	got, skips, err := h.Mailboxes()
	want := []Mailbox{{}, {Domain: "example.com", Box: "user"}}
	if err != nil || !slices.Equal(got, want) || len(skips) != 0 {
		t.Fatalf("mailboxes %+v, skips %+v, error %v", got, skips, err)
	}
}

func TestMailboxesWithoutEtc(t *testing.T) {
	_, h := openTenant(t)
	got, skips, err := h.Mailboxes()
	if err != nil || !slices.Equal(got, []Mailbox{{}}) || len(skips) != 0 {
		t.Fatalf("mailboxes %+v, skips %+v, error %v", got, skips, err)
	}
}
