package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// A scan report shows each finding's context in both the text and the JSON
// form, so an operator reading `csm scan --report` sees ModSecurity is off
// for the account the malware was found on.
func TestScanReportShowsFindingContext(t *testing.T) {
	const context = "ModSecurity is disabled for account alice (all domains) (set in /etc/apache2/conf.d/userdata/ssl/2_4/alice/modsec.conf): requests there are not filtered and leave no modsec audit record."
	job := store.ScanJobRecord{ID: "job-context", Scope: "account", Target: "alice", State: "done"}
	findings := []alert.Finding{{
		Severity: alert.Critical,
		Check:    "webshell",
		Message:  "Known webshell found: /home/alice/public_html/x.php",
		Details:  "Size: 10",
		Context:  context,
		FilePath: "/home/alice/public_html/x.php",
		TenantID: "alice",
	}}

	var text bytes.Buffer
	printScanReportTo(job.ID, false, &text, makeScanReportSender(job, findings))
	if !strings.Contains(text.String(), context) || !strings.Contains(text.String(), "Size: 10") {
		t.Errorf("text report lacks details or context:\n%s", text.String())
	}

	var raw bytes.Buffer
	printScanReportTo(job.ID, true, &raw, makeScanReportSender(job, findings))
	if !strings.Contains(raw.String(), `"context": "ModSecurity is disabled for account alice`) &&
		!strings.Contains(raw.String(), `"context":"ModSecurity is disabled for account alice`) {
		t.Errorf("JSON report lacks context:\n%s", raw.String())
	}
}
