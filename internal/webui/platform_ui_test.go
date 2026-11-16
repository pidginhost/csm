package webui

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

// renderRealPage renders ui/templates/<page>.html inside the real layout
// with the server's own template functions.
func renderRealPage(t *testing.T, s *Server, page string) string {
	t.Helper()
	tmpl, err := template.New(page+".html").Funcs(s.templateFuncs()).
		ParseFiles("../../ui/templates/layout.html", "../../ui/templates/"+page+".html")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, page+".html", map[string]string{"Hostname": "host.example"}); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestLayoutRendersEmailEntryOnlyWithMail(t *testing.T) {
	s := newTestServer(t, "tok")
	setTestPlatform(s, platform.PanelNone, platform.MTAPostfix)
	if out := renderRealPage(t, s, "audit"); !strings.Contains(out, `href="/email"`) {
		t.Error("sidebar lacks Email Security on a host with a mail server")
	}
	setTestPlatform(s, platform.PanelNone, platform.MTAUnknown)
	out := renderRealPage(t, s, "audit")
	if strings.Contains(out, `href="/email"`) || strings.Contains(out, `data-csm-route="email"`) {
		t.Error("sidebar shows Email Security on a host with no mail server")
	}
	if !strings.Contains(out, `href="/firewall"`) {
		t.Error("sidebar lost an ungated entry")
	}
}

func getPage(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleEmail(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func TestHandleEmailRedirectsWithoutMail(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	setTestPlatform(s, platform.PanelNone, platform.MTAUnknown)
	w := getPage(t, s, "/email")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/dashboard" {
		t.Fatalf("status %d Location %q, want 303 to /dashboard", w.Code, w.Header().Get("Location"))
	}
}

func TestHandleEmailRendersWithMail(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	setTestPlatform(s, platform.PanelNone, platform.MTAStalwart)
	if w := getPage(t, s, "/email"); w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
}

// cpanelOnlyEmailIDs are the Email Security elements that need the
// cPanel/Exim backends; the rest work on any detected mail server.
var cpanelOnlyEmailIDs = []string{
	"email-tab-queue", "email-pane-queue", "kpi-queue",
	"email-tab-held", "email-pane-held",
	"email-tab-forwarders", "email-pane-forwarders",
	"email-tab-delays", "email-pane-delays",
	"prot-av", "prot-watcher",
}

var anyMailEmailIDs = []string{
	"email-tab-overview", "email-pane-overview",
	"email-tab-rejects", "email-pane-rejects",
	"email-tab-sending", "email-pane-sending",
	"email-tab-findings", "email-pane-findings",
	"kpi-tagged", "kpi-malware", "kpi-other", "kpi-logins", "prot-smtp",
}

// suspendedEmailIDs need a mail server CSM can suspend mailboxes on:
// cPanel, or Stalwart through its API.
var suspendedEmailIDs = []string{"email-tab-suspended", "email-pane-suspended"}

// rspamdEmailIDs describe CSM's own antispam, which a Stalwart host does
// not run beside its filter.
var rspamdEmailIDs = []string{"email-rspamd", "prot-antispam"}

func TestEmailPageRendersByFeature(t *testing.T) {
	s := newTestServer(t, "tok")
	has := func(out, id string) bool { return strings.Contains(out, `id="`+id+`"`) }

	for _, host := range []struct {
		name  string
		panel platform.Panel
		mta   platform.MTAKind
	}{
		{"postfix", platform.PanelNone, platform.MTAPostfix},
		{"exim without cpanel", platform.PanelNone, platform.MTAExim},
		{"stalwart on plesk", platform.PanelPlesk, platform.MTAStalwart},
	} {
		setTestPlatform(s, host.panel, host.mta)
		out := renderRealPage(t, s, "email")
		for _, id := range anyMailEmailIDs {
			if !has(out, id) {
				t.Errorf("%s: %s missing", host.name, id)
			}
		}
		for _, id := range cpanelOnlyEmailIDs {
			if has(out, id) {
				t.Errorf("%s: %s rendered without its backend", host.name, id)
			}
		}
		for _, id := range suspendedEmailIDs {
			if has(out, id) != (host.mta == platform.MTAStalwart) {
				t.Errorf("%s: %s rendered %v", host.name, id, has(out, id))
			}
		}
		for _, id := range rspamdEmailIDs {
			if has(out, id) != (host.mta != platform.MTAStalwart) {
				t.Errorf("%s: %s rendered %v", host.name, id, has(out, id))
			}
		}
		if strings.Contains(out, "tab=queue") || strings.Contains(out, "tab=held") {
			t.Errorf("%s: page links to a tab it does not render", host.name)
		}
	}

	setTestPlatform(s, platform.PanelCPanel, platform.MTAExim)
	out := renderRealPage(t, s, "email")
	for _, id := range append(append(append(append([]string{}, anyMailEmailIDs...), cpanelOnlyEmailIDs...), suspendedEmailIDs...), rspamdEmailIDs...) {
		if !has(out, id) {
			t.Errorf("cpanel: %s missing", id)
		}
	}
}

// Each loader behind a gated tab returns before it calls its API when the
// feature is off; counts for those tabs load on every tab otherwise.
func TestEmailLoadersRespectFeatures(t *testing.T) {
	js, err := os.ReadFile("../../ui/static/js/email.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(js)
	for fn, flag := range map[string]string{
		"function loadQueue() {":                   "mailQueue",
		"function loadQueueComposition() {":        "mailQueue",
		"function loadHeldMail(countOnly) {":       "mailHeld",
		"function loadSuspended() {":               "mailSuspensions",
		"function loadForwarders() {":              "mailForwarders",
		"function loadDeliverability(countOnly) {": "mailDeferrals",
		"function loadAVStatus() {":                "emailAV",
	} {
		i := strings.Index(text, fn)
		if i < 0 {
			t.Errorf("%s not found", fn)
			continue
		}
		body := text[i+len(fn):]
		guard := "if (!CSM.feature('" + flag + "')) return;"
		if !strings.HasPrefix(strings.TrimSpace(body), guard) {
			t.Errorf("%s must start with %s", fn, guard)
		}
	}
}

// A bookmark to a tab this host does not render opens Overview.
func TestEmailDeepLinkFallsBackToOverview(t *testing.T) {
	js, err := os.ReadFile("../../ui/static/js/email.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), "tabButton(name) ? name : 'overview'") {
		t.Error("tabFromURL no longer falls back to overview for a tab that is not rendered")
	}
}

func TestCpanelWordingFollowsPlatform(t *testing.T) {
	s := newTestServer(t, "tok")
	cases := []struct {
		page   string
		cpanel string
		other  string
	}{
		{"firewall", "Inspect and manage dynamic blocks, allow rules, subnet bans, and cPanel lockout cleanup.", "Inspect and manage dynamic blocks, allow rules and subnet bans."},
		{"firewall", "Enter an IP to check direct blocks, subnet coverage, and cPanel lockout status.", "Enter an IP to check direct blocks and subnet coverage."},
		{"findings", "Run every security check on a single cPanel account.", "Run every security check on a single account."},
		{"findings", `for="scan-account">cPanel account</label>`, `for="scan-account">Account</label>`},
		{"incident", "for a source IP or cPanel account.", "for a source IP or account."},
	}
	for _, c := range cases {
		setTestPlatform(s, platform.PanelCPanel, platform.MTAExim)
		if out := renderRealPage(t, s, c.page); !strings.Contains(out, c.cpanel) || strings.Contains(out, c.other) {
			t.Errorf("%s on cPanel: want %q only", c.page, c.cpanel)
		}
		setTestPlatform(s, platform.PanelNone, platform.MTAPostfix)
		out := renderRealPage(t, s, c.page)
		if !strings.Contains(out, c.other) {
			t.Errorf("%s off cPanel: missing %q", c.page, c.other)
		}
	}
	// Off cPanel no page names cPanel or cPHulk in its markup.
	setTestPlatform(s, platform.PanelNone, platform.MTAPostfix)
	for _, page := range []string{"firewall", "findings", "incident", "email"} {
		out := renderRealPage(t, s, page)
		// The config block lists check labels by name; markup starts after it.
		if i := strings.Index(out, "</head>"); i >= 0 {
			out = out[i:]
		}
		for _, word := range []string{"cPanel", "cPHulk"} {
			if strings.Contains(out, word) {
				t.Errorf("%s off cPanel still says %s", page, word)
			}
		}
	}
}

// cPHulk exists only on cPanel: its buttons and its place in the confirm
// texts depend on the cphulk feature.
func TestFirewallCphulkUIIsFeatureGated(t *testing.T) {
	js, err := os.ReadFile("../../ui/static/js/firewall.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(js)
	for _, marker := range []string{`fw-cphulk-btn" href`, `lookup-cphulk-btn" data-ip`, `<strong>cPHulk:</strong>`} {
		found := false
		for _, line := range strings.Split(text, "\n") {
			if !strings.Contains(line, marker) {
				continue
			}
			found = true
			if !strings.HasPrefix(strings.TrimSpace(line), "if (CSM.feature('cphulk')) ") {
				t.Errorf("line with %s is not behind the cphulk feature: %s", marker, strings.TrimSpace(line))
			}
		}
		if !found {
			t.Errorf("marker %s not found", marker)
		}
	}
	for _, want := range []string{
		"CSM.feature('cphulk') ? ' from CSM and cPHulk?' : ' from CSM?'",
		"CSM.feature('cphulk') ? ' and cPHulk history.' : '.'",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("firewall.js missing %s", want)
		}
	}
}
