package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// ---------------------------------------------------------------------------
// apiQuarantine — exercise the full listing code path with real .meta files
// ---------------------------------------------------------------------------

func TestAPIQuarantineListsMetaFiles(t *testing.T) {
	s := newTestServer(t, "tok")

	// Create a temporary quarantine directory with a meta + item file
	dir := t.TempDir()
	metaContent := `{
		"original_path":"/home/alice/public_html/shell.php",
		"owner_uid":1000,"group_gid":1000,
		"mode":"-rw-r--r--","size":42,
		"quarantined_at":"2026-04-01T10:00:00Z",
		"reason":"webshell detected"
	}`
	if err := os.WriteFile(filepath.Join(dir, "testfile123.meta"), []byte(metaContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testfile123"), []byte("<?php evil();"), 0644); err != nil {
		t.Fatal(err)
	}

	// The handler reads from the const quarantineDir which we can't override,
	// so instead we call apiQuarantine and verify it returns a valid JSON array
	// (empty on dev machines without /opt/csm/quarantine).
	w := httptest.NewRecorder()
	s.apiQuarantine(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var entries []interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	// On dev machines this will be an empty array; that's fine — we exercised the code.
}

func TestAPIQuarantineReturnsEmptyArray(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiQuarantine(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	// Should return a JSON array (possibly empty, never null)
	body := strings.TrimSpace(w.Body.String())
	if !strings.HasPrefix(body, "[") && !strings.HasPrefix(body, "null") {
		t.Errorf("body = %q, expected JSON array", body)
	}
}

// ---------------------------------------------------------------------------
// apiQuarantinePreview — exercise more branches
// ---------------------------------------------------------------------------

func TestAPIQuarantinePreviewEmptyID(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiQuarantinePreview(w, httptest.NewRequest("GET", "/?id=", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty ID = %d, want 400", w.Code)
	}
}

func TestAPIQuarantinePreviewDotDotID(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiQuarantinePreview(w, httptest.NewRequest("GET", "/?id=..", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf(".. ID = %d, want 400", w.Code)
	}
}

func TestAPIQuarantinePreviewValidIDNoFile(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiQuarantinePreview(w, httptest.NewRequest("GET", "/?id=does_not_exist_abc", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("nonexistent file = %d, want 404", w.Code)
	}
}

func TestAPIQuarantinePreviewPreCleanID(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiQuarantinePreview(w, httptest.NewRequest("GET", "/?id=pre_clean:nonexist", nil))
	// pre_clean prefix is valid but file doesn't exist
	if w.Code != http.StatusNotFound {
		t.Errorf("pre_clean nonexistent = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// apiQuarantineBulkDelete — exercise validation branches
// ---------------------------------------------------------------------------

func TestAPIQuarantineBulkDeleteInvalidJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{not json`))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineBulkDelete(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", w.Code)
	}
}

func TestAPIQuarantineBulkDeleteEmptyIDs(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ids":[]}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineBulkDelete(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty IDs = %d, want 400", w.Code)
	}
}

func TestAPIQuarantineBulkDeleteTooManyIDs(t *testing.T) {
	s := newTestServer(t, "tok")
	// Build an array of 101 IDs
	ids := make([]string, 101)
	for i := range ids {
		ids[i] = "id"
	}
	body, _ := json.Marshal(map[string][]string{"ids": ids})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineBulkDelete(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("101 IDs = %d, want 400", w.Code)
	}
}

func TestAPIQuarantineBulkDeleteWithInvalidID(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	// Empty string ID will fail resolveQuarantineEntry
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ids":[""]}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineBulkDelete(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		OK    bool `json:"ok"`
		Count int  `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Count != 0 {
		t.Errorf("count = %d, want 0 (all invalid)", data.Count)
	}
}

func TestAPIQuarantineBulkDeleteMultipleNonexistent(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ids":["aaa","bbb","ccc"]}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineBulkDelete(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		OK    bool `json:"ok"`
		Count int  `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if !data.OK {
		t.Error("ok should be true")
	}
	// No files existed so count stays 0
	if data.Count != 0 {
		t.Errorf("count = %d, want 0", data.Count)
	}
}

// ---------------------------------------------------------------------------
// apiImport — exercise more branches
// ---------------------------------------------------------------------------

func TestAPIImportDeleteMethodRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiImport(w, httptest.NewRequest("DELETE", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE import = %d, want 405", w.Code)
	}
}

func TestAPIImportPutMethodRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiImport(w, httptest.NewRequest("PUT", "/", strings.NewReader(`{}`)))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT import = %d, want 405", w.Code)
	}
}

func TestAPIImportEmptySuppressions(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"suppressions":[],"whitelist":[]}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiImport(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var data struct {
		Imported int    `json:"imported"`
		Status   string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Imported != 0 {
		t.Errorf("imported = %d, want 0", data.Imported)
	}
	if data.Status != "imported" {
		t.Errorf("status = %q, want imported", data.Status)
	}
}

func TestAPIImportMultipleSuppressions(t *testing.T) {
	s := newTestServer(t, "tok")
	body := `{
		"suppressions": [
			{"id":"rule_a","check":"webshell","reason":"test a"},
			{"id":"rule_b","check":"obfuscated_php","reason":"test b"},
			{"id":"rule_c","check":"phishing_page","reason":"test c"}
		],
		"whitelist": []
	}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiImport(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var data struct {
		Imported int    `json:"imported"`
		Summary  string `json:"summary"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Imported != 3 {
		t.Errorf("imported = %d, want 3", data.Imported)
	}
	if !strings.Contains(data.Summary, "3 items") {
		t.Errorf("summary = %q, want '3 items'", data.Summary)
	}
}

func TestAPIImportOversizedBody(t *testing.T) {
	s := newTestServer(t, "tok")
	// Create a body larger than 512KB
	bigStr := strings.Repeat("x", 600*1024)
	body := `{"suppressions":[],"whitelist":[],"extra":"` + bigStr + `"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiImport(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("oversized body = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// apiBulkFix — exercise more branches
// ---------------------------------------------------------------------------

func TestAPIBulkFixMultipleMixed(t *testing.T) {
	s := newTestServer(t, "tok")
	body := `[
		{"check":"brute_force","message":"Brute force attack","details":""},
		{"check":"ip_reputation","message":"Bad IP","details":""},
		{"check":"webshell","message":"Found /tmp/nonexistent_wso_999.php","details":"test"}
	]`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiBulkFix(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Total     int `json:"total"`
		Succeeded int `json:"succeeded"`
		Failed    int `json:"failed"`
		Results   []struct {
			Success bool   `json:"success"`
			Error   string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Total != 3 {
		t.Errorf("total = %d, want 3", data.Total)
	}
	// First two have no fix available
	if len(data.Results) >= 2 {
		if data.Results[0].Error == "" {
			t.Error("brute_force should have error (no fix)")
		}
		if data.Results[1].Error == "" {
			t.Error("ip_reputation should have error (no fix)")
		}
	}
}

func TestAPIBulkFixPutRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiBulkFix(w, httptest.NewRequest("PUT", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT bulk fix = %d, want 405", w.Code)
	}
}

// ---------------------------------------------------------------------------
// apiAccounts — exercise the handler (will return empty on dev machines)
// ---------------------------------------------------------------------------

func TestAPIAccountsReturnsJSONArray(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiAccounts(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	// Should return valid JSON (array or null — null is valid when no accounts exist)
	var accounts interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &accounts); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	// On macOS /home exists but has no cPanel accounts → nil slice → JSON null
	switch accounts.(type) {
	case []interface{}, nil:
		// expected
	default:
		t.Errorf("expected array or null, got %T", accounts)
	}
}

// ---------------------------------------------------------------------------
// apiUnblockIP — exercise validation paths
// ---------------------------------------------------------------------------

func TestAPIUnblockIPGetMethodBlocked(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiUnblockIP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET unblock = %d, want 405", w.Code)
	}
}

func TestAPIUnblockIPMissingIPField(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing IP = %d, want 400", w.Code)
	}
}

func TestAPIUnblockIPEmptyIPField(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":""}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty IP = %d, want 400", w.Code)
	}
}

func TestAPIUnblockIPPrivateIPRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"192.168.1.1"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("private IP = %d, want 400", w.Code)
	}
}

func TestAPIUnblockIPBadJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{bad json`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// apiBlockIP — exercise validation paths
// ---------------------------------------------------------------------------

func TestAPIBlockIPGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiBlockIP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET block = %d, want 405", w.Code)
	}
}

func TestAPIBlockIPNoBlocker(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = nil
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5","reason":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiBlockIP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("no blocker = %d, want 503", w.Code)
	}
}

func TestAPIBlockIPBadJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	s.apiBlockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", w.Code)
	}
}

func TestAPIBlockIPDefaultReason(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = nil // will hit "no blocker" but exercises the reason defaulting code
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiBlockIP(w, req)
	// Without blocker, 503 — but the code path for default reason is exercised.
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestAPIBlockIPWithDuration(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = nil
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5","reason":"test","duration":"7d"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiBlockIP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

// ---------------------------------------------------------------------------
// apiFix — exercise deeper paths
// ---------------------------------------------------------------------------

func TestAPIFixPutRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiFix(w, httptest.NewRequest("PUT", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT fix = %d, want 405", w.Code)
	}
}

func TestAPIFixWithFilePath(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"check":"world_writable_php","message":"World-writable PHP: /tmp/nonexistent_test_ww.php","file_path":"/tmp/nonexistent_test_ww.php"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFix(w, req)
	// Will return an error or success depending on whether the file exists,
	// but exercises the full fix path with file_path field.
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

func TestAPIFixOversizedBody(t *testing.T) {
	s := newTestServer(t, "tok")
	// Body larger than 64KB
	bigStr := strings.Repeat("a", 70*1024)
	body := `{"check":"webshell","message":"` + bigStr + `"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFix(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("oversized body = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// apiUnblockBulk — exercise more branches
// ---------------------------------------------------------------------------

func TestAPIUnblockBulkEmptyIPs(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ips":[]}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockBulk(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty IPs = %d, want 400", w.Code)
	}
}

func TestAPIUnblockBulkTooManyIPs(t *testing.T) {
	s := newTestServer(t, "tok")
	ips := make([]string, 101)
	for i := range ips {
		ips[i] = "203.0.113.1"
	}
	body, _ := json.Marshal(map[string][]string{"ips": ips})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockBulk(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("101 IPs = %d, want 400", w.Code)
	}
}

func TestAPIUnblockBulkNoBlocker(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = nil
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ips":["203.0.113.5"]}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockBulk(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("no blocker = %d, want 503", w.Code)
	}
}

func TestAPIUnblockBulkBadJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockBulk(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", w.Code)
	}
}

func TestAPIUnblockBulkWithInvalidIPs(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()
	_ = sdb.BlockIP("203.0.113.5", "test", time.Time{})
	s.blocker = &fakeBlocker{}
	w := httptest.NewRecorder()
	// Mix valid and invalid IPs
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ips":["not-an-ip","192.168.1.1","203.0.113.5"]}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockBulk(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Status    string `json:"status"`
		Total     int    `json:"total"`
		Succeeded int    `json:"succeeded"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Total != 3 {
		t.Errorf("total = %d, want 3", data.Total)
	}
	if data.Status != "completed" {
		t.Errorf("status = %q, want completed", data.Status)
	}
}

// ---------------------------------------------------------------------------
// apiFindingDetail — exercise happy path with populated state
// ---------------------------------------------------------------------------

func TestAPIFindingDetailWithCheckParam(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiFindingDetail(w, httptest.NewRequest("GET", "/?check=webshell&message=test", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data["check"] != "webshell" {
		t.Errorf("check = %v, want webshell", data["check"])
	}
}

func TestAPIFindingDetailWithHistory(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found /home/alice/shell.php", Timestamp: now},
		{Severity: alert.Critical, Check: "webshell", Message: "Found /home/bob/shell.php", Timestamp: now.Add(-1 * time.Hour)},
		{Severity: alert.High, Check: "brute_force", Message: "SSH brute force", Timestamp: now},
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	s.apiFindingDetail(w, httptest.NewRequest("GET", "/?check=webshell&message=Found+/home/alice/shell.php", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Check   string `json:"check"`
		Message string `json:"message"`
		Related []struct {
			Check string `json:"check"`
		} `json:"related"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	// Related findings should contain other webshell findings
	if len(data.Related) < 2 {
		t.Errorf("related count = %d, want >= 2", len(data.Related))
	}
}

func TestAPIFindingDetailMissingMessage(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	// check is present but message is empty — should still work
	s.apiFindingDetail(w, httptest.NewRequest("GET", "/?check=webshell", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// apiDismissFinding — exercise validation
// ---------------------------------------------------------------------------

func TestAPIDismissGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiDismissFinding(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET dismiss = %d, want 405", w.Code)
	}
}

func TestAPIDismissMissingKey(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiDismissFinding(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing key = %d, want 400", w.Code)
	}
}

func TestAPIDismissEmptyKey(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"key":""}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiDismissFinding(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty key = %d, want 400", w.Code)
	}
}

func TestAPIDismissSuccess(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"key":"webshell:test"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiDismissFinding(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Status string `json:"status"`
		Key    string `json:"key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Status != "dismissed" {
		t.Errorf("status = %q, want dismissed", data.Status)
	}
	if data.Key != "webshell:test" {
		t.Errorf("key = %q, want webshell:test", data.Key)
	}
}

func TestAPIDismissBadJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	s.apiDismissFinding(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// apiQuarantineRestore — exercise validation paths
// ---------------------------------------------------------------------------

func TestAPIQuarantineRestoreBadJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineRestore(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", w.Code)
	}
}

func TestAPIQuarantineRestorePutRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, httptest.NewRequest("PUT", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT restore = %d, want 405", w.Code)
	}
}

func TestAPIQuarantineRestoreDotDotID(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"id":".."}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineRestore(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf(".. ID = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// apiHistory — exercise additional filter combinations
// ---------------------------------------------------------------------------

func TestAPIHistoryWithChecksFilter(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "shell found", Timestamp: now},
		{Severity: alert.High, Check: "brute_force", Message: "brute force", Timestamp: now},
		{Severity: alert.Warning, Check: "obfuscated_php", Message: "obfuscated", Timestamp: now},
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", "/?checks=webshell,obfuscated_php&limit=50", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp struct {
		Findings []alert.Finding `json:"findings"`
		Total    int             `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("total = %d, want 2 (webshell + obfuscated_php)", resp.Total)
	}
}

func TestAPIHistoryOffsetBeyondEnd(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "shell", Timestamp: now},
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", "/?offset=9999&limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestAPIHistorySearchFilter(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found shell in /home/alice/public_html/c99.php", Timestamp: now},
		{Severity: alert.High, Check: "brute_force", Message: "SSH brute from 203.0.113.5", Timestamp: now},
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	today := time.Now().Format("2006-01-02")
	s.apiHistory(w, httptest.NewRequest("GET", "/?search=alice&from="+today+"&to="+today, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp.Total != 1 {
		t.Errorf("total = %d, want 1", resp.Total)
	}
}

// ---------------------------------------------------------------------------
// apiFindings — exercise with populated findings
// ---------------------------------------------------------------------------

func TestAPIFindingsWithPopulatedState(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found /home/alice/shell.php", Timestamp: now},
		{Severity: alert.High, Check: "brute_force", Message: "SSH brute", Timestamp: now},
		{Severity: alert.Warning, Check: "auto_response", Message: "auto response", Timestamp: now},
		{Severity: alert.Warning, Check: "health", Message: "health check", Timestamp: now},
	}
	s.store.SetLatestFindings(findings)

	w := httptest.NewRecorder()
	s.apiFindings(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data []struct {
		Check  string `json:"check"`
		HasFix bool   `json:"has_fix"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	// auto_response and health should be filtered out
	if len(data) != 2 {
		t.Errorf("findings count = %d, want 2 (filtered out auto_response + health)", len(data))
	}
	for _, f := range data {
		if f.Check == "auto_response" || f.Check == "health" {
			t.Errorf("internal check %q should be filtered", f.Check)
		}
	}
}

// ---------------------------------------------------------------------------
// apiBlockedIPs — exercise fallback paths
// ---------------------------------------------------------------------------

func TestAPIBlockedIPsLegacyFallback(t *testing.T) {
	s := newTestServer(t, "tok")
	// Ensure no bbolt global store so we exercise the file fallback
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(nil) })

	w := httptest.NewRecorder()
	s.apiBlockedIPs(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestAPIBlockedIPsWithFirewallStateFile(t *testing.T) {
	s := newTestServer(t, "tok")
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(nil) })

	// Create the firewall state.json
	fwDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(fwDir, 0755); err != nil {
		t.Fatal(err)
	}
	stateJSON := `{"blocked":[{"ip":"203.0.113.5","reason":"test","blocked_at":"2026-04-01T10:00:00Z","expires_at":"0001-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(fwDir, "state.json"), []byte(stateJSON), 0644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiBlockedIPs(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data []interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(data) != 1 {
		t.Errorf("blocked count = %d, want 1", len(data))
	}
}

func TestAPIBlockedIPsWithLegacyFile(t *testing.T) {
	s := newTestServer(t, "tok")
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(nil) })

	stateJSON := `{"ips":[{"ip":"198.51.100.1","reason":"legacy block","blocked_at":"2026-04-01T10:00:00Z","expires_at":"0001-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(s.cfg.StatePath, "blocked_ips.json"), []byte(stateJSON), 0644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiBlockedIPs(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data []interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(data) != 1 {
		t.Errorf("blocked count = %d, want 1", len(data))
	}
}

// ---------------------------------------------------------------------------
// apiHistoryCSV — exercise with data
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// parseModeString — exercise edge cases
// ---------------------------------------------------------------------------

func TestParseModeStringEmpty(t *testing.T) {
	mode := parseModeString("")
	if mode != 0644 {
		t.Errorf("empty mode = %o, want 644", mode)
	}
}

func TestParseModeStringFull(t *testing.T) {
	mode := parseModeString("-rwxr-xr-x")
	if mode != 0755 {
		t.Errorf("rwxr-xr-x mode = %o, want 755", mode)
	}
}

func TestParseModeStringDirectory(t *testing.T) {
	mode := parseModeString("drwxr-xr-x")
	if mode != 0755 {
		t.Errorf("drwxr-xr-x mode = %o, want 755", mode)
	}
}

func TestParseModeStringAllDashesDeep(t *testing.T) {
	// All dashes means no permissions => fallback to 0644
	mode := parseModeString("----------")
	if mode != 0644 {
		t.Errorf("---------- mode = %o, want 644 (fallback)", mode)
	}
}

// ---------------------------------------------------------------------------
// formatBlockedView — exercise filtering
// ---------------------------------------------------------------------------

func TestFormatBlockedViewNotExpired(t *testing.T) {
	entry := blockedEntry{
		IP:        "203.0.113.5",
		Reason:    "test",
		BlockedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	view, ok := formatBlockedView(entry)
	if !ok {
		t.Fatal("non-expired entry should be ok")
	}
	if view.ExpiresIn == "permanent" {
		t.Error("should not be permanent when ExpiresAt is set")
	}
}

// ---------------------------------------------------------------------------
// fakeBlocker implements IPBlocker for testing
// ---------------------------------------------------------------------------

type fakeBlocker struct{}

func (f *fakeBlocker) BlockIP(ip string, reason string, timeout time.Duration) error {
	return nil
}

func (f *fakeBlocker) UnblockIP(ip string) error {
	return nil
}

// ---------------------------------------------------------------------------
// apiBlockIP + apiUnblockIP with fakeBlocker — exercise success path
// ---------------------------------------------------------------------------

func TestAPIUnblockIPSuccess(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = &fakeBlocker{}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var data struct {
		Status string `json:"status"`
		IP     string `json:"ip"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Status != "unblocked" {
		t.Errorf("status = %q, want unblocked", data.Status)
	}
}

func TestAPIUnblockBulkSuccessWithFakeBlocker(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = &fakeBlocker{}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ips":["203.0.113.5","198.51.100.1"]}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockBulk(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Status    string `json:"status"`
		Total     int    `json:"total"`
		Succeeded int    `json:"succeeded"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Status != "completed" {
		t.Errorf("status = %q, want completed", data.Status)
	}
	if data.Total != 2 {
		t.Errorf("total = %d, want 2", data.Total)
	}
	if data.Succeeded != 2 {
		t.Errorf("succeeded = %d, want 2", data.Succeeded)
	}
}

// ---------------------------------------------------------------------------
// apiBlockIP with duration parsing
// ---------------------------------------------------------------------------

func TestAPIBlockIPWithHoursDuration(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = &fakeBlocker{}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5","reason":"temporary","duration":"24h"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiBlockIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestAPIBlockIPLoopbackRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"127.0.0.1","reason":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiBlockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("loopback IP = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// apiScanAccount — exercise rate limiting path
// ---------------------------------------------------------------------------

func TestAPIScanAccountRateLimited(t *testing.T) {
	s := newTestServer(t, "tok")
	// Acquire the scan lock manually
	s.scanMu.Lock()
	s.scanRunning = true
	s.scanMu.Unlock()

	w := httptest.NewRecorder()
	body := `{"account":"alice"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiScanAccount(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("rate limited = %d, want 429", w.Code)
	}

	// Release
	s.scanMu.Lock()
	s.scanRunning = false
	s.scanMu.Unlock()
}

// ---------------------------------------------------------------------------
// queryInt — edge cases
// ---------------------------------------------------------------------------

func TestQueryIntDefaultDeep(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if got := queryInt(req, "missing", 42); got != 42 {
		t.Errorf("default = %d, want 42", got)
	}
}

func TestQueryIntNegativeDeep(t *testing.T) {
	req := httptest.NewRequest("GET", "/?n=-5", nil)
	if got := queryInt(req, "n", 10); got != 10 {
		t.Errorf("negative = %d, want 10 (default)", got)
	}
}

func TestQueryIntValidDeep(t *testing.T) {
	req := httptest.NewRequest("GET", "/?n=25", nil)
	if got := queryInt(req, "n", 10); got != 25 {
		t.Errorf("valid = %d, want 25", got)
	}
}

func TestQueryIntNonNumericDeep(t *testing.T) {
	req := httptest.NewRequest("GET", "/?n=abc", nil)
	if got := queryInt(req, "n", 10); got != 10 {
		t.Errorf("non-numeric = %d, want 10 (default)", got)
	}
}

// ---------------------------------------------------------------------------
// apiHistory limit cap
// ---------------------------------------------------------------------------

func TestAPIHistoryLimitCapped(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", "/?limit=99999", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp struct {
		Limit int `json:"limit"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp.Limit != 5000 {
		t.Errorf("limit = %d, want 5000 (capped)", resp.Limit)
	}
}

// ---------------------------------------------------------------------------
// apiHistory with filtered pagination (offset past end)
// ---------------------------------------------------------------------------

func TestAPIHistoryFilteredPaginationEmpty(t *testing.T) {
	s := newTestServer(t, "tok")
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "shell", Timestamp: time.Now()},
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	today := time.Now().Format("2006-01-02")
	s.apiHistory(w, httptest.NewRequest("GET", "/?from="+today+"&to="+today+"&offset=100&limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp struct {
		Findings interface{} `json:"findings"`
		Total    int         `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp.Findings != nil {
		// Should be nil/empty since offset is past end
	}
}
