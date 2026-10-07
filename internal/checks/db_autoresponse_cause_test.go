package checks

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
)

// Ruling R9: the addresses of WordPress sessions active on a compromised
// site are not attributable (the site owner's are among them), so they are
// reported, not blocked: the notice names them and the database finding
// that caused it, and carries no address another responder could act on.
func TestSessionIPNoticeNamesTheAddressesAndItsCause(t *testing.T) {
	cause := alert.Cause{FindingID: "0123456789abcdef", Check: "db_siteurl_hijack"}
	got := sessionIPsNotice([]string{"203.0.113.7", "203.0.113.8"}, "active session on hijacked site, DB: db1", cause)
	if got.Check != "auto_response" || got.Severity != alert.Warning || got.SourceIP != "" || len(got.CIDRs) != 0 ||
		!strings.Contains(got.Message, "2 addresses") || !strings.Contains(got.Details, "203.0.113.7") || !strings.Contains(got.Details, "203.0.113.8") ||
		got.Cause == nil || *got.Cause != cause {
		t.Fatalf("notice = %+v", got)
	}
	raw, err := json.Marshal(got)
	if err != nil || strings.Contains(string(raw), `"cause"`) {
		t.Fatalf("public JSON %s (error %v) names the cause", raw, err)
	}
}

// Session reports remain action output, not latest scan findings.
func TestSessionIPNoticeStaysVolatile(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	st.SetLatestFindings([]alert.Finding{{Check: "auto_response", Message: "old session report"}})
	notice := sessionIPsNotice([]string{"203.0.113.7"}, "example.com", alert.Cause{})
	StoreLatestScanFindings(st, []string{"db_siteurl_hijack"}, []alert.Finding{notice})
	for _, f := range st.LatestFindings() {
		if f.Check == "auto_response" || f.Check == "auto_block" {
			t.Fatalf("action persisted as latest scan state: %+v", f)
		}
	}
}
