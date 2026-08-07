package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The Blocks table must offer bulk unblock: a select-all header checkbox,
// per-row checkboxes, and an action button that posts the selection to the
// existing /api/v1/unblock-bulk endpoint and offers the returned undo token.
func TestFirewallBlockedTableRendersBulkSelection(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/firewall.html")
	if err != nil {
		t.Fatal(err)
	}
	js, err := os.ReadFile("../../ui/static/js/firewall.js")
	if err != nil {
		t.Fatal(err)
	}
	html := string(tmpl)
	text := string(js)

	if !strings.Contains(html, `id="blocked-bulk-unblock-btn"`) {
		t.Fatal("firewall.html missing bulk unblock button in Blocked IPs card")
	}
	if !strings.Contains(html, `blocked-bulk-unblock-btn" class="btn btn-outline-danger btn-sm d-none"`) {
		t.Fatal("bulk unblock button must start hidden until a row is selected")
	}
	for _, want := range []string{
		`id="select-all-blocked"`,
		`fw-blocked-cb`,
		`/api/v1/unblock-bulk`,
		`CSM.undo.offer`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("firewall.js missing bulk unblock hook %q", want)
		}
	}
}

// Select-all must only select checkboxes in rows the table currently shows
// (CSM.Table hides filtered/other-page rows with style.display none), so an
// operator filtering to one source cannot mass-unblock unseen entries.
func TestFirewallBlockedSelectAllSkipsHiddenRows(t *testing.T) {
	js, err := os.ReadFile("../../ui/static/js/firewall.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(js)
	start := strings.Index(text, "function visibleBlockedCheckboxes(")
	if start < 0 {
		t.Fatal("firewall.js missing visibleBlockedCheckboxes helper")
	}
	end := strings.Index(text[start:], "\n}")
	if end < 0 {
		t.Fatal("visibleBlockedCheckboxes helper not terminated")
	}
	fn := text[start : start+end]
	if !strings.Contains(fn, `row.style.display === 'none'`) || !strings.Contains(fn, "return") {
		t.Fatal("firewall.js select-all must skip rows hidden by table filters/pagination")
	}
}

// The bulk endpoint cap must fit one full Blocks page (page-size options go
// up to 250 plus All), so one selection round-trips as one request and one
// undo token. 500 IPs is accepted; 501 is rejected loudly.
func TestAPIUnblockBulkAccepts500IPs(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.blocker = newFullBlocker()

	ips := make([]string, 0, 501)
	for _, base := range []string{"192.0.2.", "198.51.100."} {
		for i := 0; i < 250; i++ {
			ips = append(ips, fmt.Sprintf("%s%d", base, i))
		}
	}
	body, _ := json.Marshal(map[string]interface{}{"ips": ips[:500]})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockBulk(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("bulk unblock of 500 IPs = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	ips = append(ips, "203.0.113.9")
	body, _ = json.Marshal(map[string]interface{}{"ips": ips})
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockBulk(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bulk unblock of 501 IPs = %d, want 400", w.Code)
	}
}
