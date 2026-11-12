package daemon

import (
	"fmt"
	"testing"
	"time"
)

// A spray split across spellings of one mailbox ("User@", "user@", padded)
// is one target, as the SMTP tracker already counts it. Folding only the
// domain let each spelling stay below the distinct-source threshold.
func TestMailAccountSprayFoldsMailboxSpellings(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	tr := newMailAuthTracker(1000, 1000, 3, 10*time.Minute, time.Hour, 0, 0, 10000, func() time.Time { return now })
	spellings := []string{"Alice@Example.COM", "alice@example.com", " ALICE@example.com "}
	var sprays int
	for i, account := range spellings {
		for _, f := range tr.Record(fmt.Sprintf("203.0.113.%d", 10+i), account) {
			if f.Check == "mail_account_spray" {
				sprays++
				if f.Mailbox != "alice@example.com" {
					t.Errorf("spray names %q, want the folded mailbox", f.Mailbox)
				}
			}
		}
	}
	if sprays != 1 {
		t.Fatalf("mail_account_spray findings = %d, want 1 across three spellings", sprays)
	}
}

func TestNormalizeMailAuthAccountMatchesSMTPFold(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"Alice@Example.COM", "alice@example.com"},
		{" bob@example.net\t", "bob@example.net"},
		{"CPUSER", "cpuser"},
		{"", ""},
	} {
		if got := normalizeMailAuthAccount(tt.in); got != tt.want {
			t.Errorf("normalizeMailAuthAccount(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
