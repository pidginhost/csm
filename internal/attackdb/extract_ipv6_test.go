package attackdb

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A full IPv6 source, including trailing zero groups, keys its own record.
func TestRecordFindingKeepsTrailingIPv6Groups(t *testing.T) {
	db := NewForTest(nil)
	db.RecordFinding(alert.Finding{Check: "smtp_bruteforce", SourceIP: "2a01:4f8:1c17:abcd::", Timestamp: time.Now()})
	if db.LookupIP("2a01:4f8:1c17:abcd::") == nil {
		t.Fatal("the IPv6 source did not key its record")
	}
}
