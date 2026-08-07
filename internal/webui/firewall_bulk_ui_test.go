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

// Every CSM.Table render can change the visible selection. Recounting from
// its onRender hook keeps the action label and select-all state aligned after
// debounced search, filters, sorting, page-size changes, and pagination.
func TestFirewallBlockedSelectionSyncsAfterTableRender(t *testing.T) {
	js, err := os.ReadFile("../../ui/static/js/firewall.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(js)
	buttonFn := firewallJSFunction(t, text, "function updateBlockedBulkButton(")
	for _, want := range []string{
		"selectAll.indeterminate",
		"selectAll.checked",
	} {
		if !strings.Contains(buttonFn, want) {
			t.Errorf("firewall.js missing blocked-selection sync %q", want)
		}
	}
	tableStart := strings.Index(text, "_fwTables.blocked = new CSM.Table({")
	if tableStart < 0 {
		t.Fatal("firewall.js missing blocked CSM.Table setup")
	}
	tableEnd := strings.Index(text[tableStart:], "\n            });")
	if tableEnd < 0 {
		t.Fatal("firewall.js blocked CSM.Table setup not terminated")
	}
	tableConfig := text[tableStart : tableStart+tableEnd]
	if !strings.Contains(tableConfig, "onRender: updateBlockedBulkButton") {
		t.Fatal("blocked CSM.Table must synchronize selection after every render")
	}
}

// Adding the checkbox column shifts every sortable column by one. Existing
// saved sort indexes must be migrated instead of silently sorting the wrong
// column (or the empty checkbox column) after upgrade.
func TestFirewallBlockedTableMigratesSavedSortColumn(t *testing.T) {
	js, err := os.ReadFile("../../ui/static/js/firewall.js")
	if err != nil {
		t.Fatal(err)
	}
	fn := firewallJSFunction(t, string(js), "function blockedTableStateKey(")
	for _, want := range []string{
		"csm-firewall-blocked-selectable",
		"state.sortCol += 1",
	} {
		if !strings.Contains(fn, want) {
			t.Errorf("firewall.js missing blocked-table state migration %q", want)
		}
	}
}

func firewallJSFunction(t *testing.T, text, signature string) string {
	t.Helper()
	start := strings.Index(text, signature)
	if start < 0 {
		t.Fatalf("firewall.js missing %s", signature)
	}
	end := strings.Index(text[start:], "\n}")
	if end < 0 {
		t.Fatalf("firewall.js function %s not terminated", signature)
	}
	return text[start : start+end]
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

func TestAPIUnblockBulkCanonicalizesIPs(t *testing.T) {
	s := newTestServer(t, "tok")
	blocker := newRecordingBlocker()
	s.blocker = blocker

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ips":[" 2001:0db8:0:0:0:0:0:5 "]}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockBulk(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("bulk unblock status = %d; body=%s", w.Code, w.Body.String())
	}
	blocker.mu.Lock()
	defer blocker.mu.Unlock()
	if len(blocker.unblocks) != 1 || blocker.unblocks[0] != "2001:db8::5" {
		t.Fatalf("unblocked IPs = %q, want canonical IPv6", blocker.unblocks)
	}
}

// apiFirewallUnban reports validation failures as HTTP 200 with
// {"success": false, "error_msg": ...}; unbanEverywhere must check that flag
// instead of toasting success for a failed unban.
func TestFirewallUnbanEverywhereSurfacesBackendFailure(t *testing.T) {
	js, err := os.ReadFile("../../ui/static/js/firewall.js")
	if err != nil {
		t.Fatal(err)
	}
	fn := firewallJSFunction(t, string(js), "function unbanEverywhere(")
	failureCheck := strings.Index(fn, "if (data && data.success === false)")
	errorToast := strings.Index(fn, "CSM.toast('Error: ' + (data.error_msg || 'Unban failed'), 'error');")
	failureReturn := strings.Index(fn, "return;")
	successToast := strings.Index(fn, "CSM.toast(msg, 'success');")
	if failureCheck < 0 || errorToast < failureCheck {
		t.Fatal("unbanEverywhere must surface the backend error_msg when success is false")
	}
	if failureReturn < errorToast || successToast < failureReturn {
		t.Fatal("unbanEverywhere must stop before reporting a failed unban as successful")
	}
}
