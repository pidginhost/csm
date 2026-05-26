package incident

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// TestKeyFor_CanonicalizesMailboxAndDomain asserts findings about the
// same mailbox land on the SAME correlation key regardless of whether
// the emitter set Mailbox to the full local@domain form, set Mailbox
// to the local part with Domain on the side, or set both. Without
// canonicalization, an actor whose findings come from two emitters
// using different conventions splits into separate incidents.
func TestKeyFor_CanonicalizesMailboxAndDomain(t *testing.T) {
	full := KeyFor(alert.Finding{Mailbox: "alice@example.com"})
	split := KeyFor(alert.Finding{Mailbox: "alice", Domain: "example.com"})
	both := KeyFor(alert.Finding{Mailbox: "alice@example.com", Domain: "example.com"})

	if full.Mailbox != "alice@example.com" {
		t.Errorf("full-form mailbox not preserved: %q", full.Mailbox)
	}
	if split.Mailbox != "alice@example.com" {
		t.Errorf("split-form mailbox not canonicalised: %q", split.Mailbox)
	}
	if both.Mailbox != "alice@example.com" {
		t.Errorf("both-form mailbox not canonicalised: %q", both.Mailbox)
	}
	if keyString(full) != keyString(split) {
		t.Errorf("full and split keys disagree: %q vs %q", keyString(full), keyString(split))
	}
	if keyString(full) != keyString(both) {
		t.Errorf("full and both keys disagree: %q vs %q", keyString(full), keyString(both))
	}
}

// TestKeyFor_DomainOnlyFindingsStillKeyDistinctly: a Domain-only
// finding (no mailbox) should not silently inherit a fake mailbox.
// Domain alone is still a valid grouping dimension.
func TestKeyFor_DomainOnlyFindingsStillKeyDistinctly(t *testing.T) {
	k := KeyFor(alert.Finding{Domain: "example.com"})
	if k.Mailbox != "" {
		t.Errorf("domain-only key gained synthetic mailbox: %q", k.Mailbox)
	}
	if k.Domain != "example.com" {
		t.Errorf("domain-only key lost Domain: %q", k.Domain)
	}
}

// TestKeyFor_MailboxAlreadyHasDomainButDifferent: when Mailbox has
// "alice@example.com" but Domain="other.com", trust the Mailbox @-
// form; do not overwrite with the conflicting Domain.
func TestKeyFor_MailboxAlreadyHasDomainButDifferent(t *testing.T) {
	k := KeyFor(alert.Finding{Mailbox: "alice@example.com", Domain: "other.com"})
	if k.Mailbox != "alice@example.com" {
		t.Errorf("Mailbox @-form should win over conflicting Domain: %q", k.Mailbox)
	}
}
