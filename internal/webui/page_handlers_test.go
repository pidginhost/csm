package webui

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

// newTestServerWithTemplates creates a test server with minimal stub templates
// so page handlers can render without errors.
func newTestServerWithTemplates(t *testing.T, token string) *Server {
	t.Helper()
	s := newTestServer(t, token)
	s.cfg.Firewall = &firewall.FirewallConfig{}
	s.templates = make(map[string]*template.Template)

	// All page handlers call ExecuteTemplate(w, "page.html", data) which
	// expects a template named "page.html" in the set. Create minimal
	// stubs that accept any data and output "OK".
	pages := []string{
		"dashboard", "findings", "quarantine", "firewall", "modsec",
		"modsec-rules", "threat", "rules", "audit", "account",
		"incident", "email", "performance", "hardening", "login",
	}
	for _, page := range pages {
		name := page + ".html"
		tmpl := template.Must(template.New(name).Parse("OK"))
		s.templates[name] = tmpl
	}
	s.hasUI = true
	return s
}

// --- handleDashboard --------------------------------------------------

func TestHandleDashboardRendersOK(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleDashboard(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
	if w.Body.String() != "OK" {
		t.Errorf("body = %q", w.Body.String())
	}
}

// --- handleFindings ---------------------------------------------------

func TestHandleFindingsRendersOK(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleFindings(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

// --- handleHistoryRedirect -------------------------------------------

func TestHandleHistoryRedirect(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/history?check=test", nil)
	s.handleHistoryRedirect(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/findings?tab=history&check=test" {
		t.Errorf("Location = %q", loc)
	}
}

func TestHandleHistoryRedirectNoQuery(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.handleHistoryRedirect(w, httptest.NewRequest("GET", "/history", nil))
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/findings?tab=history" {
		t.Errorf("Location = %q", loc)
	}
}

// --- handleQuarantine / handleFirewall / handleEmail -------------------

func TestHandleQuarantineRendersOK(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleQuarantine(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandleFirewallRendersOK(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleFirewall(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandleEmailRendersOK(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleEmail(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

// --- Other page handlers (threat, rules, audit, etc.) -----------------

func TestHandleThreatRendersOK(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleThreat(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandleRulesRendersOK(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleRules(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandleAuditRendersOK(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleAudit(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandlePerformanceRendersOK(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handlePerformance(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandleHardeningRendersOK(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleHardening(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandleIncidentRendersOK(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleIncident(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandleAccountRendersOK(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleAccount(w, httptest.NewRequest("GET", "/?name=alice", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandleAccountRedirectsMissingName(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleAccount(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
}
