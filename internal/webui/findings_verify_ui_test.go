package webui

import (
	"os"
	"strings"
	"testing"
)

// TestFindingsJSWiresVerifyAction pins the "Re-check" finding action: the
// button must exist, bind via addEventListener (no inline handler), and POST
// to the verify endpoint so an operator can confirm a manual fix without
// waiting for the next scan.
func TestFindingsJSWiresVerifyAction(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/findings.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	for _, want := range []string{
		"verify-btn",
		"/api/v1/verify-finding",
		"function verifyOne(",
		"verifyBtn.addEventListener('click'",
		// Button is gated on has_verify so it never appears on findings that
		// have no automated re-check (e.g. brute_force, ip_reputation).
		"data-hasVerify=",
		"if (hasVerify)",
		`' data-details="' + CSM.esc(f.details || '') + '"'`,
		"details: row.getAttribute('data-details') || '',",
		"details: i.details",
		// Content fingerprints stay server-owned; the browser sends identity
		// and path context only.
		"file_path: row.getAttribute('data-filepath') || ''",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("findings.js missing verify-action fragment %q", want)
		}
	}
	for _, banned := range []string{
		"data-contentsha=",
		"content_sha256: row.getAttribute('data-contentsha')",
	} {
		if strings.Contains(js, banned) {
			t.Errorf("findings.js still forwards client-controlled fingerprint %q", banned)
		}
	}
}
