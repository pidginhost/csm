package attackdb

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// An attacker record is keyed on the finding's structured source address
// only. Message text can name a destination, a process name or a path an
// attacker chose; none of it is evidence that the address attacked the host.
func TestRecordFindingKeysOnSourceIPOnly(t *testing.T) {
	db := NewForTest(nil)
	now := time.Now()
	for _, f := range []alert.Finding{
		{Check: "user_outbound_connection", Message: "Non-root user connecting to unusual destination: 203.0.113.20:443"},
		{Check: "fake_kernel_thread", Message: "Non-root process masquerading as kernel thread: [203.0.113.21]"},
		{Check: "suspicious_process", Message: "Suspicious process name: 203.0.113.22"},
		{Check: "webshell", Message: "Known webshell found: /home/alice/public_html/a from 203.0.113.23 b/x.php"},
		{Check: "mail_per_account", Message: "High email volume from [203.0.113.24]: 900 messages"},
		{Check: "wp_login_bruteforce", SourceIP: "999.999.999.999", Message: "WordPress brute force from 203.0.113.25"},
	} {
		f.Timestamp = now
		db.RecordFinding(f)
	}
	if n := len(db.TopAttackers(100)); n != 0 {
		t.Fatalf("message text created %d attacker records: %+v", n, db.TopAttackers(100))
	}

	db.RecordFinding(alert.Finding{Check: "wp_login_bruteforce", SourceIP: "203.0.113.30", Message: "WordPress brute force from 203.0.113.31", Timestamp: now})
	if db.LookupIP("203.0.113.30") == nil || db.LookupIP("203.0.113.31") != nil {
		t.Fatal("the record was not keyed on the structured source address")
	}
}
