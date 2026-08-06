package checks

import (
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/platform"
)

// cpanelInfo is the platform shape these scopes only ever exist on:
// cPanel with Apache-style config layout.
func cpanelInfo() platform.Info {
	return platform.Info{
		Panel:           platform.PanelCPanel,
		WebServer:       platform.WSApache,
		ApacheConfigDir: "/etc/apache2",
	}
}

// globFS answers Glob and ReadFile from a fixed path->content map.
// Glob support is deliberately literal: the production code is expected
// to expand one wildcard segment per pattern, so the fake matches any
// stored path whose shape lines up with the pattern.
type globFS struct {
	mockOS
	files     map[string]string
	readPaths []string
}

func newGlobFS(files map[string]string) *globFS {
	f := &globFS{files: files}
	f.readFile = func(name string) ([]byte, error) {
		f.readPaths = append(f.readPaths, name)
		if body, ok := f.files[name]; ok {
			return []byte(body), nil
		}
		return nil, os.ErrNotExist
	}
	f.glob = func(pattern string) ([]string, error) {
		var out []string
		for p := range f.files {
			if globMatch(pattern, p) {
				out = append(out, p)
			}
		}
		return out, nil
	}
	return f
}

// globMatch compares pattern and path segment by segment, treating "*"
// as "exactly one non-empty segment".
func globMatch(pattern, path string) bool {
	pp := strings.Split(pattern, "/")
	sp := strings.Split(path, "/")
	if len(pp) != len(sp) {
		return false
	}
	for i := range pp {
		if pp[i] == "*" {
			if sp[i] == "" {
				return false
			}
			continue
		}
		if pp[i] != sp[i] {
			return false
		}
	}
	return true
}

func scopeSources(scopes []modsecDisabledScope) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		out = append(out, s.Source)
	}
	return out
}

func hasScopeFor(t *testing.T, scopes []modsecDisabledScope, source string) modsecDisabledScope {
	t.Helper()
	for _, s := range scopes {
		if s.Source == source {
			return s
		}
	}
	t.Fatalf("no disabled scope reported for %s; got %v", source, scopeSources(scopes))
	return modsecDisabledScope{}
}

// The per-domain userdata flag is the mechanism that silently voids every
// CSM virtual patch for one vhost while leaving no modsec audit trail.
func TestModsecDisabledScopes_PerDomainUserdataFlag(t *testing.T) {
	old := osFS
	defer SetOS(old)
	SetOS(newGlobFS(map[string]string{
		"/var/cpanel/userdata/alice/example.com": "documentroot: /home/alice/public_html\nsecruleengineoff: 1\n",
	}))

	scopes := modsecDisabledScopes(cpanelInfo())

	got := hasScopeFor(t, scopes, "/var/cpanel/userdata/alice/example.com")
	if got.User != "alice" {
		t.Errorf("user = %q, want alice", got.User)
	}
	if got.Domain != "example.com" {
		t.Errorf("domain = %q, want example.com", got.Domain)
	}
}

// secruleengineoff: 0 is the enabled state and must never be reported.
func TestModsecDisabledScopes_IgnoresEnabledUserdataFlag(t *testing.T) {
	old := osFS
	defer SetOS(old)
	SetOS(newGlobFS(map[string]string{
		"/var/cpanel/userdata/alice/example.com": "secruleengineoff: 0\n",
	}))

	if scopes := modsecDisabledScopes(cpanelInfo()); len(scopes) != 0 {
		t.Fatalf("expected no scopes for an enabled domain, got %v", scopeSources(scopes))
	}
}

// The account-wide file disables ModSecurity for every vhost the account
// owns and is not driven by userdata, so a userdata-only audit misses it.
func TestModsecDisabledScopes_AccountWideStdTree(t *testing.T) {
	old := osFS
	defer SetOS(old)
	SetOS(newGlobFS(map[string]string{
		"/etc/apache2/conf.d/userdata/std/2_4/bob/modsec.conf": "<IfModule mod_security2.c>\nSecRuleEngine Off\n</IfModule>\n",
	}))

	scopes := modsecDisabledScopes(cpanelInfo())

	got := hasScopeFor(t, scopes, "/etc/apache2/conf.d/userdata/std/2_4/bob/modsec.conf")
	if got.User != "bob" {
		t.Errorf("user = %q, want bob", got.User)
	}
	if got.Domain != "" {
		t.Errorf("domain = %q, want empty for an account-wide scope", got.Domain)
	}
}

// Nearly all traffic is HTTPS, so a scope that lives only in the ssl tree
// is the one that actually decides whether attacks are filtered.
func TestModsecDisabledScopes_AccountWideSSLTree(t *testing.T) {
	old := osFS
	defer SetOS(old)
	SetOS(newGlobFS(map[string]string{
		"/etc/apache2/conf.d/userdata/ssl/2_4/bob/modsec.conf": "SecRuleEngine Off\n",
	}))

	scopes := modsecDisabledScopes(cpanelInfo())
	hasScopeFor(t, scopes, "/etc/apache2/conf.d/userdata/ssl/2_4/bob/modsec.conf")
}

func TestModsecDisabledScopes_DomainLevelConf(t *testing.T) {
	old := osFS
	defer SetOS(old)
	SetOS(newGlobFS(map[string]string{
		"/etc/apache2/conf.d/userdata/ssl/2_4/bob/shop.example/modsec.conf": "SecRuleEngine Off\n",
	}))

	scopes := modsecDisabledScopes(cpanelInfo())

	got := hasScopeFor(t, scopes, "/etc/apache2/conf.d/userdata/ssl/2_4/bob/shop.example/modsec.conf")
	if got.User != "bob" {
		t.Errorf("user = %q, want bob", got.User)
	}
	if got.Domain != "shop.example" {
		t.Errorf("domain = %q, want shop.example", got.Domain)
	}
}

// A file that only carries rule exclusions leaves the engine on and is a
// legitimate operator workaround, not a finding.
func TestModsecDisabledScopes_IgnoresEngineOnWithExclusions(t *testing.T) {
	old := osFS
	defer SetOS(old)
	SetOS(newGlobFS(map[string]string{
		"/etc/apache2/conf.d/userdata/std/2_4/bob/modsec.conf": "SecRuleEngine On\nSecRuleRemoveById 942190\n",
	}))

	if scopes := modsecDisabledScopes(cpanelInfo()); len(scopes) != 0 {
		t.Fatalf("expected no scopes when the engine is on, got %v", scopeSources(scopes))
	}
}

// cPanel stores the same flag in <domain>, <domain>_SSL and <domain>.cache.
// Reporting one domain three times would bury the operator in duplicates.
func TestModsecDisabledScopes_DeduplicatesUserdataSiblings(t *testing.T) {
	old := osFS
	defer SetOS(old)
	SetOS(newGlobFS(map[string]string{
		"/var/cpanel/userdata/alice/example.com":       "secruleengineoff: 1\n",
		"/var/cpanel/userdata/alice/example.com_SSL":   "secruleengineoff: 1\n",
		"/var/cpanel/userdata/alice/example.com.cache": `{"secruleengineoff":1}`,
	}))

	scopes := modsecDisabledScopes(cpanelInfo())

	if len(scopes) != 1 {
		t.Fatalf("expected 1 scope for one domain, got %d: %v", len(scopes), scopeSources(scopes))
	}
	if scopes[0].Domain != "example.com" {
		t.Errorf("domain = %q, want example.com", scopes[0].Domain)
	}
}

// The userdata directory also contains account metadata, generated caches,
// and directories. None describes a vhost, and cache JSON can be large, so
// scope discovery must reject those names before trying to read them.
func TestModsecDisabledScopes_SkipsUserdataMetadataWithoutReadingIt(t *testing.T) {
	old := osFS
	defer SetOS(old)
	fs := newGlobFS(map[string]string{
		"/var/cpanel/userdata/alice/cache.json":        "secruleengineoff: 1\n",
		"/var/cpanel/userdata/alice/main":              "secruleengineoff: 1\n",
		"/var/cpanel/userdata/alice/main.cache":        "secruleengineoff: 1\n",
		"/var/cpanel/userdata/alice/nginx-cache.json":  "secruleengineoff: 1\n",
		"/var/cpanel/userdata/alice/scope":             "secruleengineoff: 1\n",
		"/var/cpanel/userdata/alice/example.com":       "secruleengineoff: 1\n",
		"/var/cpanel/userdata/alice/example.com.cache": "secruleengineoff: 1\n",
	})
	SetOS(fs)

	scopes := modsecDisabledScopes(cpanelInfo())

	if len(scopes) != 1 || scopes[0].Domain != "example.com" {
		t.Fatalf("scopes = %+v, want only example.com", scopes)
	}
	wantReads := []string{"/var/cpanel/userdata/alice/example.com"}
	if strings.Join(fs.readPaths, "\n") != strings.Join(wantReads, "\n") {
		t.Errorf("ReadFile paths = %v, want %v", fs.readPaths, wantReads)
	}
}

func TestDedupeScopes_KeepsAccountAndDomainScopesDistinct(t *testing.T) {
	scopes := dedupeScopes([]modsecDisabledScope{
		{User: "alice", Source: "/std/alice/modsec.conf"},
		{User: "alice", Domain: "example.com", Source: "/std/alice/example.com/modsec.conf"},
	})

	if len(scopes) != 2 {
		t.Fatalf("scopes = %+v, want distinct account-wide and per-domain entries", scopes)
	}
	if scopes[0].Domain != "" || scopes[1].Domain != "example.com" {
		t.Fatalf("scopes = %+v, account-wide and per-domain keys shadowed each other", scopes)
	}
}

// cPanel LiteSpeed consumes the same EA4 Apache userdata includes. Platform
// detection can identify LiteSpeed without populating ApacheConfigDir, so the
// audit must still inspect the canonical cPanel include tree.
func TestModsecDisabledScopes_LiteSpeedUsesCPanelApacheTree(t *testing.T) {
	old := osFS
	defer SetOS(old)
	const source = "/etc/apache2/conf.d/userdata/ssl/2_4/alice/example.com/modsec.conf"
	SetOS(newGlobFS(map[string]string{source: "SecRuleEngine Off\n"}))

	info := platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed}
	scopes := modsecDisabledScopes(info)

	got := hasScopeFor(t, scopes, source)
	if got.User != "alice" || got.Domain != "example.com" {
		t.Fatalf("scope = %+v, want alice/example.com", got)
	}
}

// Non-cPanel hosts have none of these paths; the check must stay silent
// rather than report phantom scopes.
func TestModsecDisabledScopes_SkipsNonCPanel(t *testing.T) {
	old := osFS
	defer SetOS(old)
	SetOS(newGlobFS(map[string]string{
		"/var/cpanel/userdata/alice/example.com": "secruleengineoff: 1\n",
	}))

	info := cpanelInfo()
	info.Panel = platform.PanelNone
	if scopes := modsecDisabledScopes(info); len(scopes) != 0 {
		t.Fatalf("expected no scopes off cPanel, got %v", scopeSources(scopes))
	}
}

func TestModsecDisabledFindings_NoneWhenAllEnabled(t *testing.T) {
	old := osFS
	defer SetOS(old)
	SetOS(newGlobFS(map[string]string{
		"/var/cpanel/userdata/alice/example.com": "secruleengineoff: 0\n",
	}))

	if f := modsecDisabledFindings(cpanelInfo()); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// One aggregated finding, not one per scope: a host can have hundreds of
// disabled domains and per-scope findings would bury every other alert.
func TestModsecDisabledFindings_AggregatesIntoSingleFinding(t *testing.T) {
	old := osFS
	defer SetOS(old)
	files := map[string]string{
		"/etc/apache2/conf.d/userdata/std/2_4/bob/modsec.conf": "SecRuleEngine Off\n",
	}
	for _, d := range []string{"a.example", "b.example", "c.example"} {
		files["/var/cpanel/userdata/alice/"+d] = "secruleengineoff: 1\n"
	}
	SetOS(newGlobFS(files))

	findings := modsecDisabledFindings(cpanelInfo())

	if len(findings) != 1 {
		t.Fatalf("expected 1 aggregated finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Check != "modsec_disabled_vhost" {
		t.Errorf("check = %q, want modsec_disabled_vhost", f.Check)
	}
	if f.Severity != alert.High {
		t.Errorf("severity = %v, want High", f.Severity)
	}
	if !strings.Contains(f.Message, "4") {
		t.Errorf("message should report 4 disabled scopes, got %q", f.Message)
	}
	for _, want := range []string{"a.example", "bob"} {
		if !strings.Contains(f.Details, want) {
			t.Errorf("details missing %q; got:\n%s", want, f.Details)
		}
	}
}

// The details block is operator-facing text, so a host with hundreds of
// disabled domains must not emit an unbounded wall of paths.
func TestModsecDisabledFindings_CapsDetailListing(t *testing.T) {
	old := osFS
	defer SetOS(old)
	files := make(map[string]string, 60)
	for _, d := range []string{
		"d01", "d02", "d03", "d04", "d05", "d06", "d07", "d08", "d09", "d10",
		"d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18", "d19", "d20",
		"d21", "d22", "d23", "d24", "d25", "d26", "d27", "d28", "d29", "d30",
	} {
		files["/var/cpanel/userdata/alice/"+d+".example"] = "secruleengineoff: 1\n"
	}
	SetOS(newGlobFS(files))

	f := modsecDisabledFindings(cpanelInfo())[0]

	// Each listed scope occupies one "  <domain> -- <source>" line.
	listed := strings.Count(f.Details, ".example -- ")
	if listed != modsecDisabledDetailCap {
		t.Errorf("details listed %d scopes, cap is %d", listed, modsecDisabledDetailCap)
	}
	if !strings.Contains(f.Details, "and 10 more") {
		t.Errorf("details should flag the 10 omitted scopes; got:\n%s", f.Details)
	}
	if !strings.Contains(f.Message, "30") {
		t.Errorf("message should state the full count of 30, got %q", f.Message)
	}
}

// On cPanel the platform layer reports ApacheConfigDir as
// /usr/local/apache/conf, and the userdata tree hangs directly off it.
// The conf.d segment belongs to the distro path (/etc/apache2/conf.d),
// which is the same directory reached another way -- it is not a
// subdirectory of the cPanel config dir.
func TestModsecDisabledScopes_CPanelApacheConfLayout(t *testing.T) {
	old := osFS
	defer SetOS(old)
	SetOS(newGlobFS(map[string]string{
		"/usr/local/apache/conf/userdata/std/2_4/bob/modsec.conf":              "SecRuleEngine Off\n",
		"/usr/local/apache/conf/userdata/ssl/2_4/bob/shop.example/modsec.conf": "SecRuleEngine Off\n",
	}))

	info := cpanelInfo()
	info.ApacheConfigDir = "/usr/local/apache/conf"

	scopes := modsecDisabledScopes(info)

	account := hasScopeFor(t, scopes, "/usr/local/apache/conf/userdata/std/2_4/bob/modsec.conf")
	if account.User != "bob" || account.Domain != "" {
		t.Errorf("account scope = %q/%q, want bob with empty domain", account.User, account.Domain)
	}
	domain := hasScopeFor(t, scopes, "/usr/local/apache/conf/userdata/ssl/2_4/bob/shop.example/modsec.conf")
	if domain.Domain != "shop.example" {
		t.Errorf("domain scope = %q, want shop.example", domain.Domain)
	}
}
