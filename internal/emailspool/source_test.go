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

func TestReadSourceMalformed(t *testing.T) {
	if _, err := ReadSource(strings.NewReader("")); err == nil {
		t.Fatal("empty input gave no error")
	}
	if _, err := ReadSource(strings.NewReader("1abcDE-000001-AB-H\n")); err == nil {
		t.Fatal("input without line 2 gave no error")
	}
	for _, bad := range []string{"-host_address garbage", "-host_address 192.0.2.10", "-host_address 999.0.2.10.25", "-host_address"} {
		if got := readSource(t, spoolHeader(bad)); got != "uid:1001" {
			t.Errorf("%q: source = %q, want uid:1001", bad, got)
		}
	}
	if got := readSource(t, spoolHeader("-aclm _x notanumber", "-host_address 192.0.2.10.25")); got != "uid:1001" {
		t.Errorf("bad ACL length: source = %q, want uid:1001 (reading must stop)", got)
	}
}
