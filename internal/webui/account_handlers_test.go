package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// --- apiAccountDetail: validation --------------------------------------

func TestAPIAccountDetailInvalidNames(t *testing.T) {
	s := newTestServer(t, "tok")
	cases := []struct {
		query string
		desc  string
	}{
		{"", "empty name"},
		{"?name=", "blank name"},
		{"?name=../etc", "path traversal"},
		{"?name=1user", "starts with digit"},
		{"?name=user;rm", "semicolon injection"},
		{"?name=<script>", "XSS attempt"},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		s.apiAccountDetail(w, httptest.NewRequest("GET", "/"+tc.query, nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", tc.desc, w.Code)
		}
	}
}

// --- apiAccountDetail: valid name with no matching data ----------------

func TestAPIAccountDetailEmptyFindings(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiAccountDetail(w, httptest.NewRequest("GET", "/?name=bob", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data["account"] != "bob" {
		t.Errorf("account = %v, want bob", data["account"])
	}
	// Verify all expected top-level keys are present
	for _, key := range []string{"account", "findings", "quarantined", "history", "whm_url"} {
		if _, ok := data[key]; !ok {
			t.Errorf("missing field %q", key)
		}
	}
}

// --- apiAccountDetail: findings filtered to the account ----------------

func TestAPIAccountDetailFiltersFindings(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found /home/alice/public_html/shell.php", Timestamp: now},
		{Severity: alert.High, Check: "brute_force", Message: "SSH brute force from 203.0.113.5", Timestamp: now},
		{Severity: alert.Warning, Check: "obfuscated_php", Message: "Obfuscated PHP in /home/bob/public_html/x.php", FilePath: "/home/bob/public_html/x.php", Timestamp: now},
		{Severity: alert.High, Check: "webshell", Message: "Webshell in /home/alice/public_html/c99.php", Timestamp: now},
	}
	s.store.SetLatestFindings(findings)
	s.store.AppendHistory(findings)

	// Query for alice: should see 2 findings (both with /home/alice/)
	w := httptest.NewRecorder()
	s.apiAccountDetail(w, httptest.NewRequest("GET", "/?name=alice", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Account  string `json:"account"`
		Findings []struct {
			Check   string `json:"check"`
			Message string `json:"message"`
			HasFix  bool   `json:"has_fix"`
		} `json:"findings"`
		History []struct {
			Check   string `json:"check"`
			Message string `json:"message"`
		} `json:"history"`
		WHMURL string `json:"whm_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Account != "alice" {
		t.Errorf("account = %q, want alice", data.Account)
	}
	if len(data.Findings) != 2 {
		t.Errorf("findings count = %d, want 2 (alice's findings only)", len(data.Findings))
	}
	for _, f := range data.Findings {
		if !strings.Contains(f.Message, "/home/alice/") {
			t.Errorf("unexpected finding for alice: %q", f.Message)
		}
	}
	// History should also be filtered to alice
	if len(data.History) != 2 {
		t.Errorf("history count = %d, want 2", len(data.History))
	}
	// WHM URL should contain the account name
	if !strings.Contains(data.WHMURL, "user=alice") {
		t.Errorf("whm_url = %q, want user=alice in URL", data.WHMURL)
	}

	// Query for bob: should see 1 finding
	w2 := httptest.NewRecorder()
	s.apiAccountDetail(w2, httptest.NewRequest("GET", "/?name=bob", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("bob status = %d", w2.Code)
	}
	var data2 struct {
		Findings []struct {
			Check string `json:"check"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &data2); err != nil {
		t.Fatalf("bob bad JSON: %v", err)
	}
	if len(data2.Findings) != 1 {
		t.Errorf("bob findings count = %d, want 1", len(data2.Findings))
	}
}

// --- apiAccountDetail: skips auto_response, auto_block, etc. -----------

func TestAPIAccountDetailSkipsInternalChecks(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.High, Check: "auto_response", Message: "Auto response /home/charlie/public_html/x.php", Timestamp: now},
		{Severity: alert.High, Check: "auto_block", Message: "Blocked IP for /home/charlie/public_html/y.php", Timestamp: now},
		{Severity: alert.Warning, Check: "check_timeout", Message: "Check timed out for /home/charlie/", Timestamp: now},
		{Severity: alert.Warning, Check: "health", Message: "Health check /home/charlie/", Timestamp: now},
		{Severity: alert.Critical, Check: "webshell", Message: "Found /home/charlie/public_html/bad.php", Timestamp: now},
	}
	s.store.SetLatestFindings(findings)

	w := httptest.NewRecorder()
	s.apiAccountDetail(w, httptest.NewRequest("GET", "/?name=charlie", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Findings []struct {
			Check string `json:"check"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(data.Findings) != 1 {
		t.Errorf("findings count = %d, want 1 (only webshell, not internal checks)", len(data.Findings))
	}
	if len(data.Findings) > 0 && data.Findings[0].Check != "webshell" {
		t.Errorf("expected webshell check, got %q", data.Findings[0].Check)
	}
}

// --- apiAccountDetail: finding matched by Details or FilePath ----------

func TestAPIAccountDetailMatchesDetailsAndFilePath(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.High, Check: "obfuscated_php", Message: "Obfuscated PHP detected", Details: "File: /home/dave/public_html/evil.php", Timestamp: now},
		{Severity: alert.Warning, Check: "world_writable_php", Message: "World-writable PHP", FilePath: "/home/dave/public_html/config.php", Timestamp: now},
	}
	s.store.SetLatestFindings(findings)

	w := httptest.NewRecorder()
	s.apiAccountDetail(w, httptest.NewRequest("GET", "/?name=dave", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Findings []struct {
			Check string `json:"check"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(data.Findings) != 2 {
		t.Errorf("findings count = %d, want 2 (matched by Details and FilePath)", len(data.Findings))
	}
}

// --- handleAccount: page handler redirects on invalid name -------------

func TestHandleAccountRedirectsOnPathTraversal(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleAccount(w, httptest.NewRequest("GET", "/?name=../etc/passwd", nil))
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 redirect", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/findings" {
		t.Errorf("Location = %q, want /findings", loc)
	}
}

func TestHandleAccountRedirectsOnSpecialChars(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleAccount(w, httptest.NewRequest("GET", "/?name=user@host", nil))
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 redirect", w.Code)
	}
}

// --- extractAccountFromFinding ----------------------------------------

func TestExtractAccountFromMessagePath(t *testing.T) {
	f := alert.Finding{
		Message: "Found webshell at /home/alice/public_html/shell.php",
	}
	got := extractAccountFromFinding(f)
	if got != "alice" {
		t.Errorf("extractAccountFromFinding() = %q, want alice", got)
	}
}

func TestExtractAccountFromFilePathField(t *testing.T) {
	f := alert.Finding{
		FilePath: "/home/bob/public_html/index.php",
	}
	got := extractAccountFromFinding(f)
	if got != "bob" {
		t.Errorf("extractAccountFromFinding() = %q, want bob", got)
	}
}

func TestExtractAccountFromDetailsHomePath(t *testing.T) {
	f := alert.Finding{
		Details: "Suspicious file found at /home/carol/public_html/x.php",
	}
	got := extractAccountFromFinding(f)
	if got != "carol" {
		t.Errorf("extractAccountFromFinding() = %q, want carol", got)
	}
}

func TestExtractAccountFromDetailsAccountPrefix(t *testing.T) {
	f := alert.Finding{
		Details: "Account: testuser more info here",
	}
	got := extractAccountFromFinding(f)
	if got != "testuser" {
		t.Errorf("extractAccountFromFinding() = %q, want testuser", got)
	}
}

func TestExtractAccountFromDetailsUserPrefix(t *testing.T) {
	f := alert.Finding{
		Details: "user: someuser additional text",
	}
	got := extractAccountFromFinding(f)
	if got != "someuser" {
		t.Errorf("extractAccountFromFinding() = %q, want someuser", got)
	}
}

func TestExtractAccountFromDetailsUserPrefixTerminal(t *testing.T) {
	// When user prefix is at the end of the string with no delimiter
	f := alert.Finding{
		Details: "user: onlyuser",
	}
	got := extractAccountFromFinding(f)
	if got != "onlyuser" {
		t.Errorf("extractAccountFromFinding() = %q, want onlyuser", got)
	}
}

func TestExtractAccountNoMatchReturnsEmpty(t *testing.T) {
	f := alert.Finding{
		Message: "SSH brute force from 1.2.3.4",
		Details: "No account info here",
	}
	got := extractAccountFromFinding(f)
	if got != "" {
		t.Errorf("extractAccountFromFinding() = %q, want empty string", got)
	}
}

// --- apiFindingsEnriched: severity counts and account extraction -------

func TestAPIFindingsEnrichedCountsAndAccounts(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found /home/alice/shell.php", Timestamp: now},
		{Severity: alert.High, Check: "brute_force", Message: "SSH brute force from 203.0.113.5", Timestamp: now},
		{Severity: alert.Warning, Check: "waf_status", Message: "WAF not active", Timestamp: now},
		{Severity: alert.Critical, Check: "obfuscated_php", Message: "Obfuscated /home/bob/x.php", Timestamp: now},
	}
	s.store.SetLatestFindings(findings)

	w := httptest.NewRecorder()
	s.apiFindingsEnriched(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Findings      []enrichedFinding `json:"findings"`
		CheckTypes    []string          `json:"check_types"`
		Accounts      []string          `json:"accounts"`
		CriticalCount int               `json:"critical_count"`
		HighCount     int               `json:"high_count"`
		WarningCount  int               `json:"warning_count"`
		Total         int               `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.CriticalCount != 2 {
		t.Errorf("critical_count = %d, want 2", data.CriticalCount)
	}
	if data.HighCount != 1 {
		t.Errorf("high_count = %d, want 1", data.HighCount)
	}
	if data.WarningCount != 1 {
		t.Errorf("warning_count = %d, want 1", data.WarningCount)
	}
	if data.Total != 4 {
		t.Errorf("total = %d, want 4", data.Total)
	}
	// Should extract accounts alice and bob
	foundAlice, foundBob := false, false
	for _, a := range data.Accounts {
		if a == "alice" {
			foundAlice = true
		}
		if a == "bob" {
			foundBob = true
		}
	}
	if !foundAlice {
		t.Error("expected alice in accounts list")
	}
	if !foundBob {
		t.Error("expected bob in accounts list")
	}
	// check_types should be sorted and non-empty
	if len(data.CheckTypes) == 0 {
		t.Error("expected non-empty check_types")
	}
}

// --- apiFindingsEnriched: skips internal checks ------------------------

func TestAPIFindingsEnrichedSkipsInternalChecks(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.High, Check: "auto_response", Message: "Killed process", Timestamp: now},
		{Severity: alert.High, Check: "auto_block", Message: "Blocked 1.2.3.4", Timestamp: now},
		{Severity: alert.Warning, Check: "check_timeout", Message: "Timeout on check", Timestamp: now},
		{Severity: alert.Warning, Check: "health", Message: "Health check", Timestamp: now},
		{Severity: alert.Critical, Check: "webshell", Message: "Found webshell", Timestamp: now},
	}
	s.store.SetLatestFindings(findings)

	w := httptest.NewRecorder()
	s.apiFindingsEnriched(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Total != 1 {
		t.Errorf("total = %d, want 1 (only webshell)", data.Total)
	}
}

// --- apiFix: POST with missing check or message -----------------------

func TestAPIFixMissingFields(t *testing.T) {
	s := newTestServer(t, "tok")
	cases := []struct {
		body string
		desc string
	}{
		{`{}`, "empty body"},
		{`{"check":"webshell"}`, "missing message"},
		{`{"message":"Found shell"}`, "missing check"},
		{`{"check":"","message":""}`, "blank fields"},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		s.apiFix(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", tc.desc, w.Code)
		}
	}
}

func TestAPIFixNoFixAvailable(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"check":"brute_force","message":"SSH brute force from 1.2.3.4"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFix(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (no fix for brute_force)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "no automated fix") {
		t.Errorf("body = %q, expected 'no automated fix' message", w.Body.String())
	}
}

// --- apiBulkFix: POST with empty array --------------------------------

func TestAPIBulkFixEmptyArray(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`[]`))
	req.Header.Set("Content-Type", "application/json")
	s.apiBulkFix(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Total     int `json:"total"`
		Succeeded int `json:"succeeded"`
		Failed    int `json:"failed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Total != 0 {
		t.Errorf("total = %d, want 0", data.Total)
	}
}

func TestAPIBulkFixInvalidBody(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	s.apiBulkFix(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAPIBulkFixWithUnfixableCheck(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `[{"check":"brute_force","message":"Brute force attack"}]`
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
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Total != 1 {
		t.Errorf("total = %d, want 1", data.Total)
	}
	if data.Failed != 1 {
		t.Errorf("failed = %d, want 1 (no fix for brute_force)", data.Failed)
	}
}

// --- apiExport: content disposition header ----------------------------

func TestAPIExportContentDisposition(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiExport(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	cd := w.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "csm-state-export.json") {
		t.Errorf("Content-Disposition = %q, want csm-state-export.json", cd)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// --- apiImport: with suppressions data --------------------------------

func TestAPIImportWithSuppressionsAndDedup(t *testing.T) {
	s := newTestServer(t, "tok")
	body := `{
		"suppressions": [
			{"id":"rule1","check":"webshell","path_pattern":"*.php","reason":"test"}
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
		Status   string `json:"status"`
		Imported int    `json:"imported"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Status != "imported" {
		t.Errorf("status = %q, want imported", data.Status)
	}
	if data.Imported != 1 {
		t.Errorf("imported = %d, want 1", data.Imported)
	}
}

func TestAPIImportDedupSuppressions(t *testing.T) {
	s := newTestServer(t, "tok")
	// Import twice with the same rule ID: second import should dedup
	body := `{"suppressions":[{"id":"rule_dedup","check":"webshell","reason":"first"}],"whitelist":[]}`
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		s.apiImport(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("import %d: status = %d", i, w.Code)
		}
	}
	// Second import should report 0 new items
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiImport(w, req)
	var data struct {
		Imported int `json:"imported"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Imported != 0 {
		t.Errorf("imported = %d, want 0 (deduped)", data.Imported)
	}
}

func TestAPIImportInvalidJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{not json`))
	req.Header.Set("Content-Type", "application/json")
	s.apiImport(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// --- apiScanAccount: validation ---------------------------------------

func TestAPIScanAccountInvalidName(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"account":"../etc/passwd"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiScanAccount(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAPIScanAccountEmptyName(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"account":""}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiScanAccount(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAPIScanAccountMissingBody(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)
	s.apiScanAccount(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// --- apiIncident: account parameter -----------------------------------

func TestAPIIncidentWithAccount(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found /home/frank/shell.php", Timestamp: now},
		{Severity: alert.High, Check: "brute_force", Message: "SSH brute force from 1.2.3.4", Timestamp: now},
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	s.apiIncident(w, httptest.NewRequest("GET", "/?account=frank", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Events       []timelineEvent `json:"events"`
		Total        int             `json:"total"`
		QueryAccount string          `json:"query_account"`
		Hours        int             `json:"hours"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.QueryAccount != "frank" {
		t.Errorf("query_account = %q, want frank", data.QueryAccount)
	}
	// Should match the finding containing /home/frank/
	if data.Total != 1 {
		t.Errorf("total = %d, want 1 (only frank's finding)", data.Total)
	}
	if data.Hours != 72 {
		t.Errorf("hours = %d, want 72 (default)", data.Hours)
	}
}

func TestAPIIncidentHoursParam(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiIncident(w, httptest.NewRequest("GET", "/?ip=1.2.3.4&hours=24", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Hours int `json:"hours"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Hours != 24 {
		t.Errorf("hours = %d, want 24", data.Hours)
	}
}

func TestAPIIncidentHoursMaxCapped(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiIncident(w, httptest.NewRequest("GET", "/?ip=1.2.3.4&hours=9999", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Hours int `json:"hours"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data.Hours != 720 {
		t.Errorf("hours = %d, want 720 (max capped)", data.Hours)
	}
}

// --- apiAccountDetail: history is capped at 100 -----------------------

func TestAPIAccountDetailHistoryCap(t *testing.T) {
	s := newTestServer(t, "tok")
	// Create 150 history entries for one account
	var findings []alert.Finding
	for i := 0; i < 150; i++ {
		findings = append(findings, alert.Finding{
			Severity:  alert.Warning,
			Check:     "world_writable_php",
			Message:   "/home/edgar/public_html/file.php is world-writable",
			Timestamp: time.Now().Add(-time.Duration(i) * time.Minute),
		})
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	s.apiAccountDetail(w, httptest.NewRequest("GET", "/?name=edgar", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		History []interface{} `json:"history"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(data.History) > 100 {
		t.Errorf("history count = %d, want <= 100 (capped)", len(data.History))
	}
}

// --- apiAccountDetail: has_fix reflects check type ---------------------

func TestAPIAccountDetailHasFix(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found /home/greg/shell.php", Timestamp: now},
		{Severity: alert.High, Check: "brute_force", Message: "Brute force from /home/greg/", Timestamp: now},
	}
	s.store.SetLatestFindings(findings)

	w := httptest.NewRecorder()
	s.apiAccountDetail(w, httptest.NewRequest("GET", "/?name=greg", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Findings []struct {
			Check  string `json:"check"`
			HasFix bool   `json:"has_fix"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	for _, f := range data.Findings {
		switch f.Check {
		case "webshell":
			if !f.HasFix {
				t.Error("webshell should have has_fix=true")
			}
		case "brute_force":
			if f.HasFix {
				t.Error("brute_force should have has_fix=false")
			}
		}
	}
}

// --- apiFindingsEnriched: enriched fields are populated ----------------

func TestAPIFindingsEnrichedFieldsPopulated(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{
			Severity:  alert.Critical,
			Check:     "webshell",
			Message:   "Found /home/alice/public_html/shell.php",
			FilePath:  "/home/alice/public_html/shell.php",
			Timestamp: now,
		},
	}
	s.store.SetLatestFindings(findings)

	w := httptest.NewRecorder()
	s.apiFindingsEnriched(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data struct {
		Findings []enrichedFinding `json:"findings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(data.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(data.Findings))
	}
	f := data.Findings[0]
	if f.Key == "" {
		t.Error("enriched finding key should not be empty")
	}
	if f.Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL", f.Severity)
	}
	if f.SevClass == "" {
		t.Error("sev_class should not be empty")
	}
	if f.Account != "alice" {
		t.Errorf("account = %q, want alice", f.Account)
	}
	if f.FilePath != "/home/alice/public_html/shell.php" {
		t.Errorf("file_path = %q, want /home/alice/public_html/shell.php", f.FilePath)
	}
	if f.FirstSeen == "" {
		t.Error("first_seen should not be empty")
	}
	if f.LastSeen == "" {
		t.Error("last_seen should not be empty")
	}
	if !f.HasFix {
		t.Error("webshell should have has_fix=true")
	}
}

// --- apiFindings: does not expose internal checks ----------------------

func TestAPIFindingsSkipsInternalChecks(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.High, Check: "auto_response", Message: "Auto action", Timestamp: now},
		{Severity: alert.High, Check: "auto_block", Message: "Auto blocked", Timestamp: now},
		{Severity: alert.Warning, Check: "check_timeout", Message: "Timed out", Timestamp: now},
		{Severity: alert.Warning, Check: "health", Message: "OK", Timestamp: now},
		{Severity: alert.Critical, Check: "webshell", Message: "Shell found", Timestamp: now},
	}
	s.store.SetLatestFindings(findings)

	w := httptest.NewRecorder()
	s.apiFindings(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data []struct {
		Check string `json:"check"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(data) != 1 {
		t.Errorf("findings count = %d, want 1 (only webshell)", len(data))
	}
}
