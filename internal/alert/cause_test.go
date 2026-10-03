package alert

import (
	"testing"
	"time"
)

func TestCauseOfNamesTheFinding(t *testing.T) {
	f := Finding{Check: "db_siteurl_hijack", Severity: Critical, Message: "hijack", Timestamp: time.Unix(1790000000, 0)}
	if got := CauseOf(f); got != (Cause{FindingID: FindingID(f), Check: "db_siteurl_hijack"}) {
		t.Fatalf("cause %+v, want the finding's identity and check", got)
	}
}
