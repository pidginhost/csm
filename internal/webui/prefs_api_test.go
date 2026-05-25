package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOperatorKeyHashesCookie(t *testing.T) {
	s := newTestServer(t, "tok")
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "csm_auth", Value: "alpha"})
	first := s.operatorKey(req)
	if first == "" || first == "alpha" {
		t.Fatalf("operatorKey returned bad value %q", first)
	}
	if len(first) != 64 { // SHA-256 hex length
		t.Fatalf("operatorKey expected SHA-256 hex, got len %d", len(first))
	}

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Authorization", "Bearer alpha")
	if got := s.operatorKey(req2); got != first {
		t.Fatalf("bearer and cookie with same token should hash equally; got %q vs %q", got, first)
	}

	req3 := httptest.NewRequest("GET", "/", nil)
	req3.AddCookie(&http.Cookie{Name: "csm_auth", Value: "beta"})
	if got := s.operatorKey(req3); got == first {
		t.Fatal("different tokens must hash to different keys")
	}

	req4 := httptest.NewRequest("GET", "/", nil)
	if got := s.operatorKey(req4); got != "" {
		t.Fatalf("missing credential should return empty key, got %q", got)
	}
}

func TestSanitizeUserPrefsClampsValues(t *testing.T) {
	in := userPrefsBlob{
		Density:     "ULTRA",
		Timezone:    "rm -rf",
		AutoRefresh: "maybe",
		TableColumns: map[string][]string{
			"good":                               {"col1", "col2"},
			"$bad":                               {"col1"},
			"too-long" + strings.Repeat("x", 64): {"col1"},
		},
	}
	out := sanitizeUserPrefs(in)
	if out.Density != "" {
		t.Errorf("density=%q should be cleared", out.Density)
	}
	if out.Timezone != "" {
		t.Errorf("timezone=%q should be cleared", out.Timezone)
	}
	if out.AutoRefresh != "" {
		t.Errorf("auto_refresh=%q should be cleared", out.AutoRefresh)
	}
	if _, ok := out.TableColumns["good"]; !ok {
		t.Errorf("good key dropped")
	}
	if _, ok := out.TableColumns["$bad"]; ok {
		t.Errorf("bad key retained")
	}
	for k := range out.TableColumns {
		if len(k) > 64 {
			t.Errorf("long key retained: %s", k)
		}
	}

	clean := userPrefsBlob{
		Density:     "compact",
		Timezone:    "Europe/Bucharest",
		AutoRefresh: "off",
	}
	got := sanitizeUserPrefs(clean)
	if got.Density != "compact" || got.Timezone != "Europe/Bucharest" || got.AutoRefresh != "off" {
		t.Errorf("clean prefs lost in sanitize: %+v", got)
	}
}

func TestSanitizeUserPrefsAcceptsKnownTimezones(t *testing.T) {
	for _, tz := range []string{"server", "local", "UTC", "America/Los_Angeles"} {
		got := sanitizeUserPrefs(userPrefsBlob{Timezone: tz}).Timezone
		if got != tz {
			t.Errorf("timezone %q dropped (got %q)", tz, got)
		}
	}
}

func TestUserPrefsRoundTrip(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")

	authReq := func(method, path string, body []byte) *http.Request {
		var br *http.Request
		if body == nil {
			br = httptest.NewRequest(method, path, nil)
		} else {
			br = httptest.NewRequest(method, path, bytes.NewReader(body))
			br.Header.Set("Content-Type", "application/json")
		}
		br.Header.Set("Authorization", "Bearer tok")
		return br
	}

	// PUT
	put := authReq("PUT", "/api/v1/prefs/user", []byte(`{"density":"compact","timezone":"UTC","auto_refresh":"off"}`))
	rec := httptest.NewRecorder()
	s.apiPrefsUser(rec, put)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", rec.Code, rec.Body.String())
	}

	// GET
	rec = httptest.NewRecorder()
	s.apiPrefsUser(rec, authReq("GET", "/api/v1/prefs/user", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", rec.Code, rec.Body.String())
	}
	var blob userPrefsBlob
	if err := json.Unmarshal(rec.Body.Bytes(), &blob); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if blob.Density != "compact" || blob.Timezone != "UTC" || blob.AutoRefresh != "off" {
		t.Fatalf("round-trip lost data: %+v", blob)
	}

	// Other operator sees empty
	rec = httptest.NewRecorder()
	other := authReq("GET", "/api/v1/prefs/user", nil)
	other.Header.Set("Authorization", "Bearer different-token")
	// Make different-token an admin token to pass requireAuth in real wiring;
	// we call the handler directly so requireAuth is bypassed but operatorKey
	// still hashes whatever credential the request carries.
	s.apiPrefsUser(rec, other)
	if rec.Code != http.StatusOK {
		t.Fatalf("other GET status=%d", rec.Code)
	}
	var otherBlob userPrefsBlob
	_ = json.Unmarshal(rec.Body.Bytes(), &otherBlob)
	if otherBlob.Density != "" || otherBlob.Timezone != "" || otherBlob.AutoRefresh != "" {
		t.Fatalf("cross-operator leak: %+v", otherBlob)
	}
}

func TestSavedViewsCRUD(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	authReq := func(method, path string, body string) *http.Request {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer tok")
		return req
	}

	// Empty list at first.
	rec := httptest.NewRecorder()
	s.apiPrefsViews(rec, authReq("GET", "/api/v1/prefs/views?page=findings", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("empty list status=%d", rec.Code)
	}
	var list []savedView
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 0 {
		t.Fatalf("expected empty, got %v", list)
	}

	// Create.
	put := authReq("PUT", "/api/v1/prefs/views",
		`{"page":"findings","name":"Critical SSH","params":{"sev":"critical","check":"smtp_bruteforce"}}`)
	rec = httptest.NewRecorder()
	s.apiPrefsViews(rec, put)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", rec.Code, rec.Body.String())
	}

	// List shows it.
	rec = httptest.NewRecorder()
	s.apiPrefsViews(rec, authReq("GET", "/api/v1/prefs/views?page=findings", ""))
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 || list[0].Name != "Critical SSH" {
		t.Fatalf("expected one view, got %v", list)
	}
	if list[0].Params["sev"] != "critical" {
		t.Fatalf("param lost: %+v", list[0].Params)
	}

	// Other page sees nothing.
	rec = httptest.NewRecorder()
	s.apiPrefsViews(rec, authReq("GET", "/api/v1/prefs/views?page=audit", ""))
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 0 {
		t.Fatalf("page filter not applied: %v", list)
	}

	// Delete.
	del := authReq("DELETE", "/api/v1/prefs/views", `{"page":"findings","name":"Critical SSH"}`)
	rec = httptest.NewRecorder()
	s.apiPrefsViews(rec, del)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Empty again.
	rec = httptest.NewRecorder()
	s.apiPrefsViews(rec, authReq("GET", "/api/v1/prefs/views?page=findings", ""))
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 0 {
		t.Fatalf("delete did not remove: %v", list)
	}
}

func TestSavedViewsRejectInvalidPage(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	put := httptest.NewRequest("PUT", "/api/v1/prefs/views", strings.NewReader(
		`{"page":"../etc","name":"bad","params":{}}`))
	put.Header.Set("Content-Type", "application/json")
	put.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	s.apiPrefsViews(rec, put)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSavedViewsRejectsControlCharsInName(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	body := "{\"page\":\"findings\",\"name\":\"bad\\u0007name\",\"params\":{}}"
	put := httptest.NewRequest("PUT", "/api/v1/prefs/views", strings.NewReader(body))
	put.Header.Set("Content-Type", "application/json")
	put.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	s.apiPrefsViews(rec, put)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for control chars, got %d", rec.Code)
	}
}
