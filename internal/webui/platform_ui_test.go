package webui

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
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
