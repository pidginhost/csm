package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeWhmapi1 puts a whmapi1 on PATH that exits with the given status.
func fakeWhmapi1(t *testing.T, exitCode int) {
	t.Helper()
	binDir := t.TempDir()
	script := "#!/bin/sh\nexit " + map[int]string{0: "0", 1: "1"}[exitCode] + "\n"
	if err := os.WriteFile(filepath.Join(binDir, "whmapi1"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func postJSON(handler func(http.ResponseWriter, *http.Request), body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler(w, req)
	return w
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return body
}

// Clearing cPHulk's history reports whether it happened. It used to answer
// "flushed" whatever whmapi1 did, including when it was not installed.
func TestCphulkClearReportsTheFlushResult(t *testing.T) {
	s := newTestServer(t, "tok")
	fakeWhmapi1(t, 1)
	assertJSONError(t, "failed flush", postJSON(s.apiFirewallFlushCphulk, `{"ip":"203.0.113.5"}`), http.StatusInternalServerError)

	fakeWhmapi1(t, 0)
	w := postJSON(s.apiFirewallFlushCphulk, `{"ip":"203.0.113.5"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body %s", w.Code, w.Body.String())
	}
	if body := decodeBody(t, w); body["ok"] != true || body["ip"] != "203.0.113.5" {
		t.Errorf("body = %v", body)
	}
}

// phclient reads /firewall/check and /firewall/unban and tests "success".
// Both keep it next to the API's own success signals, and both fail with an
// error status instead of a 200 that says success:false.
func TestFirewallCheckAndUnbanKeepThePhclientContract(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	s.blocker = newFullBlocker()
	fakeWhmapi1(t, 0)

	w := httptest.NewRecorder()
	s.apiFirewallCheck(w, httptest.NewRequest("GET", "/?ip=203.0.113.5", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("check status = %d body %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["success"] != true {
		t.Errorf("check success = %v", body["success"])
	}
	for _, key := range []string{"ip", "permanent", "temporary", "cphulk"} {
		if _, ok := body[key]; !ok {
			t.Errorf("check lost %q: %v", key, body)
		}
	}

	w = httptest.NewRecorder()
	s.apiFirewallCheck(w, httptest.NewRequest("GET", "/?ip=nope", nil))
	assertJSONError(t, "check of a bad address", w, http.StatusBadRequest)

	w = postJSON(s.apiFirewallUnban, `{"ip":"203.0.113.5"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("unban status = %d body %s", w.Code, w.Body.String())
	}
	if body := decodeBody(t, w); body["ok"] != true || body["success"] != true {
		t.Errorf("unban body = %v", body)
	}
	assertJSONError(t, "unban of a bad address", postJSON(s.apiFirewallUnban, `{"ip":"nope"}`), http.StatusBadRequest)
	assertJSONError(t, "unban without an address", postJSON(s.apiFirewallUnban, `{}`), http.StatusBadRequest)
}
