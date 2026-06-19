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
	} {
		if !strings.Contains(js, want) {
			t.Errorf("findings.js missing verify-action fragment %q", want)
		}
	}
}
