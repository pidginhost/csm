package emailspool

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

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

func TestLoadHTTPProxyRanges_BareIPs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "http_proxy_ranges.yaml"), `
version: 1
cidrs:
  - 192.0.2.10
  - "2001:db8::5"
`)
	pol, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	for ip, want := range map[string]bool{
		"192.0.2.10":  true,
		"192.0.2.11":  false,
		"2001:db8::5": true,
		"2001:db8::6": false,
	} {
		if got := pol.IsProxyIP(ip); got != want {
			t.Errorf("IsProxyIP(%s) = %v, want %v (bare IPs are /32 or /128)", ip, got, want)
		}
	}
}

func TestLoadHTTPProxyRanges_NullEntryWithValidSibling(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "http_proxy_ranges.yaml"), "version: 1\ncidrs: [null, 192.0.2.10]\n")
	pol, err := LoadPolicies(dir)
	if err == nil || !strings.Contains(err.Error(), "http_proxy_ranges.yaml") {
		t.Fatalf("LoadPolicies error = %v, want a proxy entry error", err)
	}
	if !pol.IsProxyIP("192.0.2.10") || pol.IsProxyIP("192.0.2.11") {
		t.Error("valid sibling must retain its exact address despite the null entry")
	}
	if host := firstBuiltInHost(t); pol.IsProxyIP(host) {
		t.Error("a valid operator entry must replace the built-in list")
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
	if raw.CIDRs[0] == nil {
		t.Fatal("first embedded CIDR is null")
	}
	_, n, err := net.ParseCIDR(*raw.CIDRs[0])
	if err != nil {
		t.Fatalf("first embedded CIDR %q: %v", *raw.CIDRs[0], err)
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

func TestLoadPolicies_UnusableProxyFileKeepsBuiltIn(t *testing.T) {
	cases := map[string]func(t *testing.T, path string){
		"zero bytes":     func(t *testing.T, path string) { writeFile(t, path, "") },
		"empty document": func(t *testing.T, path string) { writeFile(t, path, "---\n") },
		"no cidrs key":   func(t *testing.T, path string) { writeFile(t, path, "version: 1\n") },
		"null cidrs":     func(t *testing.T, path string) { writeFile(t, path, "version: 1\ncidrs:\n") },
		"no valid cidrs": func(t *testing.T, path string) { writeFile(t, path, "version: 1\ncidrs: [not-a-cidr, 300.1.2.3/24]\n") },
		"null entry":     func(t *testing.T, path string) { writeFile(t, path, "version: 1\ncidrs: [null]\n") },
		"blank entry":    func(t *testing.T, path string) { writeFile(t, path, "version: 1\ncidrs:\n  -\n") },
		"null alias":     func(t *testing.T, path string) { writeFile(t, path, "empty: &empty null\ncidrs: [*empty]\n") },
		"unreadable": func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			setup(t, filepath.Join(dir, "http_proxy_ranges.yaml"))
			pol, err := LoadPolicies(dir)
			if err == nil || !strings.Contains(err.Error(), "http_proxy_ranges.yaml") {
				t.Fatalf("LoadPolicies error = %v, want a http_proxy_ranges.yaml error", err)
			}
			if host := firstBuiltInHost(t); !pol.IsProxyIP(host) {
				t.Errorf("unusable operator file must leave the built-in list in force, but %s does not match", host)
			}
		})
	}
}

func TestLoadPolicies_ExplicitEmptyProxyListIsHonoured(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "http_proxy_ranges.yaml"), "version: 1\ncidrs: []\n")
	pol, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if host := firstBuiltInHost(t); pol.IsProxyIP(host) {
		t.Errorf("explicit empty list must replace the built-in list, but %s still matches", host)
	}
}

func TestReload_CorruptProxyFileKeepsPreviousOperatorList(t *testing.T) {
	for name, tc := range map[string]struct{ corrupt, wantErr string }{
		"unparsable":     {"cidrs: [\n", "parse http_proxy_ranges.yaml"},
		"zero bytes":     {"", "parse http_proxy_ranges.yaml"},
		"no valid cidrs": {"cidrs: [not-a-cidr]\n", `invalid CIDR "not-a-cidr"`},
		"null entry":     {"cidrs: [null]\n", "http_proxy_ranges.yaml"},
		"blank entry":    {"cidrs:\n  -\n", "http_proxy_ranges.yaml"},
		"null alias":     {"empty: &empty null\ncidrs: [*empty]\n", "http_proxy_ranges.yaml"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "http_proxy_ranges.yaml")
			writeFile(t, path, "version: 1\ncidrs: [198.51.100.0/24]\n")
			pol, err := LoadPolicies(dir)
			if err != nil {
				t.Fatalf("LoadPolicies: %v", err)
			}
			writeFile(t, path, tc.corrupt)
			if err := pol.Reload(dir); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Reload error = %v, want %q", err, tc.wantErr)
			}
			if !pol.IsProxyIP("198.51.100.7") {
				t.Error("corrupt reload must keep the previously loaded operator list")
			}
			if host := firstBuiltInHost(t); pol.IsProxyIP(host) {
				t.Errorf("corrupt reload must not swap in the built-in list, but %s matches", host)
			}
		})
	}
}

func TestReload_MissingProxyFileRestoresBuiltIn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "http_proxy_ranges.yaml")
	writeFile(t, path, "version: 1\ncidrs: [198.51.100.0/24]\n")
	pol, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(dir); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if pol.IsProxyIP("198.51.100.7") {
		t.Error("removed operator file must stop applying after reload")
	}
	if host := firstBuiltInHost(t); !pol.IsProxyIP(host) {
		t.Errorf("removed operator file must restore the built-in list, but %s does not match", host)
	}
}

func TestReload_NullEntriesKeepExplicitEmptyProxyList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "http_proxy_ranges.yaml")
	writeFile(t, path, "version: 1\ncidrs: [198.51.100.0/24]\n")
	pol, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	writeFile(t, path, "version: 1\ncidrs: []\n")
	if err := pol.Reload(dir); err != nil {
		t.Fatalf("Reload empty list: %v", err)
	}
	writeFile(t, path, "version: 1\ncidrs: [null, Null, NULL, ~]\n")
	if err := pol.Reload(dir); err == nil || !strings.Contains(err.Error(), "http_proxy_ranges.yaml") {
		t.Fatalf("Reload error = %v, want a proxy entry error", err)
	}
	if pol.IsProxyIP("198.51.100.7") || pol.IsProxyIP(firstBuiltInHost(t)) {
		t.Error("invalid reload must retain the last good empty list")
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
		if c == nil {
			t.Error("embedded CIDR is null")
			continue
		}
		ip, n, err := net.ParseCIDR(*c)
		if err != nil {
			t.Errorf("invalid CIDR %q: %v", *c, err)
			continue
		}
		if !ip.Equal(n.IP) {
			t.Errorf("CIDR %q has host bits set; want %s", *c, n)
		}
	}

	// Every entry sits in a provider block whose heading is followed by
	// its official source URL and retrieval date.
	sourceLine := regexp.MustCompile(`^# source: https://\S+ \(retrieved (\d{4}-\d{2}-\d{2})\)$`)
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
			m := sourceLine.FindStringSubmatch(l)
			if m == nil {
				t.Errorf("line %d: %q is not '# source: https://<url> (retrieved YYYY-MM-DD)'", i+1, l)
			} else if _, err := time.Parse(time.DateOnly, m[1]); err != nil {
				t.Errorf("line %d: retrieval date %q: %v", i+1, m[1], err)
			}
		case strings.HasPrefix(l, "- ") && !sourced:
			t.Fatalf("line %d: entry %q is outside a sourced provider block", i+1, l)
		}
	}
	if providers == 0 || providers != sources {
		t.Errorf("%d provider headings, %d source lines; want one source per provider", providers, sources)
	}
}

// CDN edges serve every visitor of the sites behind them, so the built-in
// list must carry each CDN that publishes its ranges.
func TestBuiltInProxyRanges_IncludesCDNs(t *testing.T) {
	for _, provider := range []string{"Cloudflare", "QUIC.cloud", "Fastly", "BunnyCDN", "Amazon CloudFront", "Sucuri"} {
		if !strings.Contains(string(defaultProxyRanges), "# Provider: "+provider) {
			t.Errorf("built-in proxy ranges have no %s block", provider)
		}
	}
}
