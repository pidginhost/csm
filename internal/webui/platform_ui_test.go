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
	"email-tab-suspended", "email-pane-suspended",
	"email-tab-forwarders", "email-pane-forwarders",
	"email-tab-delays", "email-pane-delays",
	"prot-av", "prot-watcher",
}

var anyMailEmailIDs = []string{
	"email-tab-overview", "email-pane-overview",
	"email-tab-rejects", "email-pane-rejects",
	"email-tab-sending", "email-pane-sending",
	"email-tab-findings", "email-pane-findings",
	"kpi-tagged", "kpi-malware", "kpi-other", "kpi-logins", "prot-antispam", "prot-smtp",
}

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
		if strings.Contains(out, "tab=queue") || strings.Contains(out, "tab=held") {
			t.Errorf("%s: page links to a tab it does not render", host.name)
		}
	}

	setTestPlatform(s, platform.PanelCPanel, platform.MTAExim)
	out := renderRealPage(t, s, "email")
	for _, id := range append(append([]string{}, anyMailEmailIDs...), cpanelOnlyEmailIDs...) {
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
