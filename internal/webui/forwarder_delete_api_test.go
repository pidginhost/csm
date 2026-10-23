package webui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mailfwd/inventory"
)

// recordedUAPI stands in for systemd-run and uapi: it records each uapi
// command and answers it with reply and err.
type recordedUAPI struct {
	calls        [][]string
	reply        string
	err          error
	noSystemdRun bool
}

func (u *recordedUAPI) lookPath(string) (string, error) {
	if u.noSystemdRun {
		return "", exec.ErrNotFound
	}
	return "/usr/bin/systemd-run", nil
}

func (u *recordedUAPI) run(_ context.Context, name string, args ...string) ([]byte, error) {
	if slices.Contains(args, "/bin/true") {
		return nil, nil
	}
	u.calls = append(u.calls, append([]string{name}, args...))
	return []byte(u.reply), u.err
}

// fwdDeleteServer serves one forwarder of shop.example, owned by owner, with
// two destinations, and records the uapi runs a delete makes.
func fwdDeleteServer(t *testing.T, source, owner string) (*Server, *recordedUAPI) {
	t.Helper()
	s := newTestServer(t, "tok")
	s.forwarderSource = fakeForwarderSource{fwds: []inventory.Forwarder{{
		Source: source,
		Domain: "shop.example",
		Owner:  owner,
		Destinations: []inventory.Destination{
			{Address: "boss@example.net", Domain: "example.net", Provider: inventory.ProviderExternal},
			{Address: "sales@shop.example", Domain: "shop.example", Provider: inventory.ProviderLocal},
		},
		KeepLocal: true,
	}}}
	u := &recordedUAPI{reply: `{"result":{"status":1,"errors":null}}`}
	s.forwarderRemover = inventory.NewCPanelRemover(u.lookPath, u.run)
	return s, u
}

func fwdDelete(s *Server, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/forwarders/delete", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	return w
}

const bossDelete = `{"source":"sales@shop.example","destination":"boss@example.net"}`

// The account uapi runs as comes from the server's own inventory, never
// from the request.
func TestForwarderDeleteRunsAsTheInventoryOwner(t *testing.T) {
	s, u := fwdDeleteServer(t, "sales@shop.example", "shopuser")

	w := fwdDelete(s, bossDelete)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d %s, want 200", w.Code, w.Body.String())
	}
	if len(u.calls) != 1 {
		t.Fatalf("uapi calls = %v, want one", u.calls)
	}
	call := u.calls[0]
	for _, want := range []string{"--user=shopuser", "delete_forwarder", "address=sales%40shop.example", "forwarder=boss%40example.net"} {
		if !slices.Contains(call, want) {
			t.Errorf("uapi argv %v lacks %q", call, want)
		}
	}
	a := lastAudit(t, s)
	if a.Action != "email_forwarder_delete" || a.Target != "sales@shop.example" ||
		!strings.Contains(a.Details, "boss@example.net") || !strings.Contains(a.Details, "shopuser") {
		t.Errorf("audit = %+v, want the delete with its destination and owner", a)
	}
}

func TestForwarderDeleteRefusesWhatTheInventoryLacks(t *testing.T) {
	for _, body := range []string{
		`{"source":"other@shop.example","destination":"boss@example.net"}`,
		`{"source":"sales@shop.example","destination":"someone@example.org"}`,
		`{"source":"SALES@shop.example","destination":"boss@example.net"}`,
	} {
		s, u := fwdDeleteServer(t, "sales@shop.example", "shopuser")
		if w := fwdDelete(s, body); w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d %s, want 404", body, w.Code, w.Body.String())
		}
		if len(u.calls) != 0 {
			t.Errorf("%s: uapi ran %v", body, u.calls)
		}
	}
}

// The default address is a domain setting in cPanel, not a forwarder that
// delete_forwarder can remove.
func TestForwarderDeleteRefusesTheDefaultAddress(t *testing.T) {
	s, u := fwdDeleteServer(t, "*@shop.example", "shopuser")
	w := fwdDelete(s, `{"source":"*@shop.example","destination":"boss@example.net"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d %s, want 400", w.Code, w.Body.String())
	}
	if len(u.calls) != 0 {
		t.Fatalf("uapi ran %v", u.calls)
	}
}

func TestForwarderDeleteNeedsAnOwner(t *testing.T) {
	s, u := fwdDeleteServer(t, "sales@shop.example", "")
	if w := fwdDelete(s, bossDelete); w.Code != http.StatusConflict {
		t.Fatalf("status %d %s, want 409", w.Code, w.Body.String())
	}
	if len(u.calls) != 0 {
		t.Fatalf("uapi ran %v", u.calls)
	}
}

func TestForwarderDeleteReportsCPanelErrors(t *testing.T) {
	s, u := fwdDeleteServer(t, "sales@shop.example", "shopuser")
	u.reply = `{"result":{"status":0,"errors":["The forwarder does not exist."]}}`
	u.err = errors.New("exit status 1")

	w := fwdDelete(s, bossDelete)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "The forwarder does not exist.") {
		t.Fatalf("status %d %s, want 500 with cPanel's error", w.Code, w.Body.String())
	}
	if a := lastAudit(t, s); a.Action != "email_forwarder_delete" || !strings.Contains(a.Details, "The forwarder does not exist.") {
		t.Errorf("audit = %+v, want the failed delete with cPanel's error", a)
	}
}

func TestForwarderDeleteNeedsSystemdRun(t *testing.T) {
	s, u := fwdDeleteServer(t, "sales@shop.example", "shopuser")
	u.noSystemdRun = true
	if w := fwdDelete(s, bossDelete); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d %s, want 503", w.Code, w.Body.String())
	}
	if len(u.calls) != 0 {
		t.Fatalf("uapi ran %v inside the sandbox", u.calls)
	}
}

func TestForwarderDeleteAuditsExecutionFailureAfterSuccessReply(t *testing.T) {
	s, u := fwdDeleteServer(t, "sales@shop.example", "shopuser")
	u.err = context.DeadlineExceeded
	w := fwdDelete(s, bossDelete)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), u.err.Error()) {
		t.Fatalf("status %d %s, want 500 with execution error", w.Code, w.Body.String())
	}
	if a := lastAudit(t, s); a.Action != "email_forwarder_delete" || !strings.Contains(a.Details, u.err.Error()) {
		t.Errorf("audit = %+v, want failed delete with execution error", a)
	}
}

func TestForwarderDeleteUnavailableOffCPanel(t *testing.T) {
	s, _ := fwdDeleteServer(t, "sales@shop.example", "shopuser")
	s.forwarderRemover = nil
	if w := fwdDelete(s, bossDelete); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d %s, want 503", w.Code, w.Body.String())
	}
}

func TestForwarderDeleteRejectsBadBodies(t *testing.T) {
	for _, body := range []string{
		`not json`,
		`{"source":"sales@shop.example"}`,
		`{"destination":"boss@example.net"}`,
		`{"source":"sales@shop.example","destination":"boss@example.net","owner":"root"}`,
	} {
		s, u := fwdDeleteServer(t, "sales@shop.example", "shopuser")
		if w := fwdDelete(s, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d %s, want 400", body, w.Code, w.Body.String())
		}
		if len(u.calls) != 0 {
			t.Errorf("%s: uapi ran %v", body, u.calls)
		}
	}
}

func TestForwarderDeleteAdminAndCSRF(t *testing.T) {
	s, u := fwdDeleteServer(t, "sales@shop.example", "shopuser")
	s.cfg.WebUI.Tokens = append(s.cfg.WebUI.Tokens, config.WebUIToken{Name: "reader", Token: "read-tok", Scope: "read", IssuedAt: time.Now().UTC().Format(time.RFC3339)})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/forwarders/delete", strings.NewReader(bossDelete))
	req.Header.Set("Authorization", "Bearer read-tok")
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("read token: status %d, want 401", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/email/forwarders/delete", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w = httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status %d, want 405", w.Code)
	}

	cookie := testBrowserCookie(t, s, "tok")
	req = httptest.NewRequest(http.MethodPost, "/api/v1/email/forwarders/delete", strings.NewReader(bossDelete))
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("browser POST without CSRF: status %d, want 403", w.Code)
	}
	if len(u.calls) != 0 {
		t.Fatalf("uapi ran %v for refused requests", u.calls)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/email/forwarders/delete", strings.NewReader(bossDelete))
	req.AddCookie(cookie)
	setSessionCSRF(s, req)
	w = httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("browser POST with CSRF: status %d %s, want 200", w.Code, w.Body.String())
	}
	if a := lastAudit(t, s); a.Via != "browser" || a.Action != "email_forwarder_delete" {
		t.Errorf("audit = %+v, want the browser's delete", a)
	}
}
