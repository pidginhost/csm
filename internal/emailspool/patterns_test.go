package emailspool

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMailerClasses(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "mailer_classes.yaml"), `
version: 1
suspicious: [PHPMailer, mass mailer]
safe: [WordPress, cPanel]
`)
	pol, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if !pol.MailerSuspicious("PHPMailer 7.0.0") {
		t.Errorf("PHPMailer should be suspicious")
	}
	if pol.MailerSafe("PHPMailer 7.0.0") {
		t.Errorf("PHPMailer should NOT be safe")
	}
	if !pol.MailerSafe("WordPress 6.4") {
		t.Errorf("WordPress should be safe")
	}
}

func TestMailerClassification_OrderedAndCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "mailer_classes.yaml"), `
version: 1
suspicious: [PHPMailer]
safe: [WordPress]
`)
	pol, _ := LoadPolicies(dir)
	if !pol.MailerSuspicious("phpmailer 5.0") {
		t.Error("case-insensitive substring match required")
	}
}

func TestLoadHTTPProxyRanges(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "http_proxy_ranges.yaml"), `
version: 1
cidrs:
  - 192.0.2.0/24
  - 2001:db8::/32
`)
	pol, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if !pol.IsProxyIP("192.0.2.10") {
		t.Errorf("192.0.2.10 should be in proxy range")
	}
	if pol.IsProxyIP("203.0.113.5") {
		t.Errorf("203.0.113.5 should NOT be in proxy range")
	}
	if !pol.IsProxyIP("2001:db8::1") {
		t.Errorf("v6 in proxy range expected")
	}
}

func TestLoadHTTPProxyRanges_InvalidCIDR(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "http_proxy_ranges.yaml"), `
version: 1
cidrs:
  - not-a-cidr
  - 192.0.2.0/24
`)
	pol, err := LoadPolicies(dir)
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if !pol.IsProxyIP("192.0.2.10") {
		t.Error("valid CIDR should still be loaded despite invalid sibling")
	}
}

// firstBuiltInHost returns the first host of the first CIDR in the embedded
// proxy list, so the tests never carry a literal provider address.
func firstBuiltInHost(t *testing.T) string {
	t.Helper()
	var raw httpProxyRangesYAML
	if err := yaml.Unmarshal(defaultProxyRanges, &raw); err != nil {
		t.Fatalf("parse embedded proxy ranges: %v", err)
	}
	if len(raw.CIDRs) == 0 {
		t.Fatal("embedded proxy ranges are empty")
	}
	_, n, err := net.ParseCIDR(raw.CIDRs[0])
	if err != nil {
		t.Fatalf("first embedded CIDR %q: %v", raw.CIDRs[0], err)
	}
	ip := slices.Clone(n.IP)
	if ones, bits := n.Mask.Size(); ones < bits {
		ip[len(ip)-1]++
	}
	return ip.String()
}

func TestLoadPolicies_MissingProxyFileUsesBuiltIn(t *testing.T) {
	pol, err := LoadPolicies(t.TempDir())
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if host := firstBuiltInHost(t); !pol.IsProxyIP(host) {
		t.Errorf("built-in range host %s must be a proxy IP when no policy file exists", host)
	}
}

func TestLoadPolicies_OperatorProxyFileReplacesBuiltIn(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "http_proxy_ranges.yaml"), "version: 1\ncidrs: [198.51.100.0/24]\n")
	pol, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if !pol.IsProxyIP("198.51.100.7") {
		t.Error("operator range must be a proxy IP")
	}
	if host := firstBuiltInHost(t); pol.IsProxyIP(host) {
		t.Errorf("operator file must replace the built-in list, but %s still matches", host)
	}
}

func TestLoadPolicies_CorruptProxyFileKeepsBuiltIn(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "http_proxy_ranges.yaml"), "cidrs: [\n")
	pol, err := LoadPolicies(dir)
	if err == nil || !strings.Contains(err.Error(), "parse http_proxy_ranges.yaml") {
		t.Fatalf("LoadPolicies error = %v, want the proxy file parse error", err)
	}
	if host := firstBuiltInHost(t); !pol.IsProxyIP(host) {
		t.Errorf("corrupt operator file must leave the built-in list in force, but %s does not match", host)
	}
}

func TestBuiltInProxyRanges_AllValid(t *testing.T) {
	var raw httpProxyRangesYAML
	if err := yaml.Unmarshal(defaultProxyRanges, &raw); err != nil {
		t.Fatalf("parse embedded proxy ranges: %v", err)
	}
	if raw.Version != 1 {
		t.Errorf("version = %d, want 1", raw.Version)
	}
	if len(raw.CIDRs) == 0 {
		t.Fatal("embedded proxy ranges are empty")
	}
	for _, c := range raw.CIDRs {
		ip, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Errorf("invalid CIDR %q: %v", c, err)
			continue
		}
		if !ip.Equal(n.IP) {
			t.Errorf("CIDR %q has host bits set; want %s", c, n)
		}
	}

	// Every entry sits in a provider block whose heading is followed by
	// its official source URL.
	lines := strings.Split(string(defaultProxyRanges), "\n")
	providers, sources := 0, 0
	sourced := false
	for i, l := range lines {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "# Provider:"):
			providers++
			sourced = i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "# source: https://")
			if !sourced {
				t.Errorf("line %d: %q is not followed by a '# source: https://' line", i+1, l)
			}
		case strings.HasPrefix(l, "# source:"):
			sources++
		case strings.HasPrefix(l, "- ") && !sourced:
			t.Fatalf("line %d: entry %q is outside a sourced provider block", i+1, l)
		}
	}
	if providers == 0 || providers != sources {
		t.Errorf("%d provider headings, %d source lines; want one source per provider", providers, sources)
	}
}
