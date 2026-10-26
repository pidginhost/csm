package emailspool

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

// spoolHeader builds an Exim -H preamble with the given option lines, then a
// recipient block and one header, as Exim writes them.
func spoolHeader(options ...string) string {
	var b strings.Builder
	b.WriteString("1abcDE-000001-AB-H\nexample 1001 1001\n<sender@example.com>\n1777409086 0\n")
	for _, o := range options {
		b.WriteString(o)
		b.WriteString("\n")
	}
	b.WriteString("1\nrcpt@example.com\n\n037  Subject: Hello\n")
	return b.String()
}

// aclLine is an ACL variable as Exim stores it: the length on the option
// line, then the value and one newline.
func aclLine(name, value string) string {
	return fmt.Sprintf("-aclm %s %d\n%s", name, len(value), value)
}

func readSource(t *testing.T, data string) string {
	t.Helper()
	got, err := ReadSource(strings.NewReader(data))
	if err != nil {
		t.Fatalf("ReadSource: %v", err)
	}
	return got
}

func TestReadSourceRemoteHost(t *testing.T) {
	if got := readSource(t, spoolHeader("-host_address 192.0.2.10.25")); got != "ip:192.0.2.10" {
		t.Fatalf("source = %q, want ip:192.0.2.10", got)
	}
}

// Exim 4.94+ marks tainted values with a second dash.
func TestReadSourceTaintedOptions(t *testing.T) {
	if got := readSource(t, spoolHeader("--host_address 192.0.2.10.25")); got != "ip:192.0.2.10" {
		t.Fatalf("tainted host source = %q, want ip:192.0.2.10", got)
	}
	if got := readSource(t, spoolHeader("-host_address 192.0.2.10.25", "--auth_id user@example.com")); got != "auth:user@example.com" {
		t.Fatalf("tainted auth source = %q, want auth:user@example.com", got)
	}
}

// Exim 4.100 writes the client as [address]:port; older releases wrote
// address.port.
func TestReadSourceBracketedHost(t *testing.T) {
	for in, want := range map[string]string{
		"-host_address [192.0.2.10]:56662":         "ip:192.0.2.10",
		"--host_address [192.0.2.10]:25":           "ip:192.0.2.10",
		"-host_address [2001:db8:1:2::5]:25":       "ip:2001:db8:1:2::/64",
		"-host_address [::ffff:198.51.100.7]:587":  "ip:198.51.100.7",
		"-host_address [2001:db8:1:2:ffff::9]:465": "ip:2001:db8:1:2::/64",
	} {
		if got := readSource(t, spoolHeader(in)); got != want {
			t.Errorf("%q: source = %q, want %q", in, got, want)
		}
	}
}

func TestReadSourceIPv6SharesSlash64(t *testing.T) {
	a := readSource(t, spoolHeader("-host_address 2001:db8:1:2::5.25"))
	b := readSource(t, spoolHeader("-host_address 2001:db8:1:2:ffff::9.25"))
	c := readSource(t, spoolHeader("-host_address 2001:db8:1:3::5.25"))
	if a != "ip:2001:db8:1:2::/64" || a != b {
		t.Fatalf("same /64 gave %q and %q, want ip:2001:db8:1:2::/64 for both", a, b)
	}
	if c == a {
		t.Fatalf("different /64 shares key %q", c)
	}
	if got := readSource(t, spoolHeader("-host_address ::ffff:192.0.2.10.25")); got != "ip:192.0.2.10" {
		t.Fatalf("mapped IPv4 source = %q, want ip:192.0.2.10", got)
	}
}

func TestReadSourceAuthWins(t *testing.T) {
	got := readSource(t, spoolHeader("-host_address 198.51.100.7.587", "-auth_id User@Example.com"))
	if got != "auth:user@example.com" {
		t.Fatalf("source = %q, want auth:user@example.com", got)
	}
}

func TestReadSourceRefusesNonASCIIAuth(t *testing.T) {
	got := readSource(t, spoolHeader("-host_address 198.51.100.7.587", "-auth_id us\x1ber@example.com"))
	if got != "ip:198.51.100.7" {
		t.Fatalf("source = %q, want the host when auth_id holds control bytes", got)
	}
	got = readSource(t, spoolHeader("-host_address 198.51.100.7.587", "-auth_id "+strings.Repeat("a", 300)))
	if got != "ip:198.51.100.7" {
		t.Fatalf("source = %q, want the host when auth_id is too long", got)
	}
}

func TestReadSourceLocalUID(t *testing.T) {
	if got := readSource(t, spoolHeader("-local")); got != "uid:1001" {
		t.Fatalf("source = %q, want uid:1001", got)
	}
}

// ACL values can carry message data. They must be skipped by length, never
// read as option lines.
func TestReadSourceSkipsACLValues(t *testing.T) {
	forgedAuth := aclLine("_x", "a\n-auth_id attacker@example.net\nb")
	if got := readSource(t, spoolHeader("-host_address 192.0.2.10.25", forgedAuth)); got != "ip:192.0.2.10" {
		t.Fatalf("source = %q, want ip:192.0.2.10 (ACL value read as an option)", got)
	}
	forgedHost := aclLine("_y", "\n-host_address 203.0.113.9.25\n")
	if got := readSource(t, spoolHeader(forgedHost, "-host_address 192.0.2.10.25")); got != "ip:192.0.2.10" {
		t.Fatalf("source = %q, want ip:192.0.2.10 (ACL value read as an option)", got)
	}
	tainted := fmt.Sprintf("--aclc 0 %d\n%s", len("\n-auth_id attacker@example.net"), "\n-auth_id attacker@example.net")
	if got := readSource(t, spoolHeader(tainted, "-local")); got != "uid:1001" {
		t.Fatalf("source = %q, want uid:1001 (tainted ACL value read as an option)", got)
	}
}

func TestReadSourceQuotedOptionsAndACL(t *testing.T) {
	value := "\n--(smtp)auth_id forged@example.net\n-host_address 203.0.113.9.25\n"
	for _, name := range []string{"acl", "aclc", "aclm"} {
		for _, prefix := range []string{"-", "--", "--(smtp)"} {
			t.Run(prefix+name, func(t *testing.T) {
				acl := fmt.Sprintf("%s%s _x %d\n%s", prefix, name, len(value), value)
				data := spoolHeader(acl, "--(smtp)host_address 192.0.2.10.25")
				if got := readSource(t, data); got != "ip:192.0.2.10" {
					t.Fatalf("source = %q, want the host after the ACL value", got)
				}
				data = spoolHeader(acl, "--(smtp)host_address 192.0.2.10.25", "--(smtp)auth_id User@Example.com")
				if got := readSource(t, data); got != "auth:user@example.com" {
					t.Fatalf("source = %q, want the auth id after the ACL value", got)
				}
			})
		}
	}
}

type countingReader struct {
	r    io.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

func TestReadSourceBounded(t *testing.T) {
	huge := fmt.Sprintf("-aclm _big %d\n", 1<<20) + strings.Repeat("x", 1<<20)
	data := spoolHeader(huge, "-host_address 203.0.113.9.25")
	cr := &countingReader{r: strings.NewReader(data)}
	got, err := ReadSource(cr)
	if err != nil {
		t.Fatalf("ReadSource: %v", err)
	}
	if got != "uid:1001" {
		t.Fatalf("source = %q, want uid:1001 from what was read before the cap", got)
	}
	if cr.read > maxSourcePreamble {
		t.Fatalf("read %d bytes, want at most %d", cr.read, maxSourcePreamble)
	}
}

func TestReadSourceACLValueAtReadLimit(t *testing.T) {
	value := strings.Repeat("x", maxSourcePreamble-1)
	data := spoolHeader("-host_address 192.0.2.10.25", aclLine("_x", value), "-auth_id forged@example.net")
	cr := &countingReader{r: strings.NewReader(data)}
	got, err := ReadSource(cr)
	if err != nil || got != "ip:192.0.2.10" {
		t.Fatalf("source = %q, %v; want host before truncated ACL value", got, err)
	}
	if cr.read != maxSourcePreamble {
		t.Fatalf("read %d bytes, want exactly the %d-byte limit", cr.read, maxSourcePreamble)
	}
}

// A read limit or truncated file must not turn part of an identity into a
// different source key. Padding before auth_id must not split one sender.
func TestReadSourceIgnoresTruncatedIdentity(t *testing.T) {
	preamble := "id-H\nexample 1001 1001\n<sender@example.com>\n0 0\n-host_address 192.0.2.10.25\n"
	for _, option := range []string{"-auth_id ", "--auth_id ", "--(smtp)auth_id "} {
		t.Run(option, func(t *testing.T) {
			for _, prefix := range []string{"u", "user", "user@example"} {
				padding := "-unused " + strings.Repeat("x", maxSourcePreamble-len(preamble)-len("-unused \n")-len(option)-len(prefix)) + "\n"
				data := preamble + padding + option + "user@example.com\n1\nrcpt@example.com\n\n"
				cr := &countingReader{r: strings.NewReader(data)}
				got, err := ReadSource(cr)
				if err != nil || got != "ip:192.0.2.10" {
					t.Errorf("limit after %q: source = %q, %v; want complete host identity", prefix, got, err)
				}
				if cr.read > maxSourcePreamble {
					t.Fatalf("read %d bytes, want at most %d", cr.read, maxSourcePreamble)
				}
			}
		})
	}
	if got := readSource(t, preamble+"-auth_id user"); got != "ip:192.0.2.10" {
		t.Errorf("truncated auth: source = %q, want complete host identity", got)
	}
	if got := readSource(t, preamble+"-auth_id user@example.com\n"); got != "auth:user@example.com" {
		t.Errorf("complete auth: source = %q, want auth:user@example.com", got)
	}
	if got, err := ReadSource(strings.NewReader("id-H\nexample 10")); err == nil {
		t.Errorf("truncated uid: source = %q, want an error", got)
	}
}

func TestReadSourceMalformed(t *testing.T) {
	if _, err := ReadSource(strings.NewReader("")); err == nil {
		t.Fatal("empty input gave no error")
	}
	if _, err := ReadSource(strings.NewReader("1abcDE-000001-AB-H\n")); err == nil {
		t.Fatal("input without line 2 gave no error")
	}
	// Line 2 of a message received over the network names Exim's own user,
	// shared by all such mail, so an unreadable host never falls back to it.
	for _, bad := range []string{"-host_address garbage", "-host_address 192.0.2.10", "-host_address 999.0.2.10.25", "-host_address", "-host_address [192.0.2.10", "-host_address [192.0.2.10]x"} {
		if got, err := ReadSource(strings.NewReader(spoolHeader(bad))); err == nil {
			t.Errorf("%q: source = %q, want an error", bad, got)
		}
	}
	if got := readSource(t, spoolHeader("-aclm _x notanumber", "-host_address 192.0.2.10.25")); got != "uid:1001" {
		t.Errorf("bad ACL length: source = %q, want uid:1001 (reading must stop)", got)
	}
}
