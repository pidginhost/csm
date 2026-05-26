package incident

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/processctx"
)

// TestKeyFor_ProcessUIDDoesNotSplitMailboxKey: two findings about
// the same mailbox observed via different processes (different UIDs)
// must hash to the same key so the threshold gate accumulates them
// into one incident. The previous KeyFor set Process.UID
// unconditionally, splitting the actor across however many processes
// the attacker happened to use.
func TestKeyFor_ProcessUIDDoesNotSplitMailboxKey(t *testing.T) {
	a := KeyFor(alert.Finding{
		Mailbox: "alice@example.com",
		Process: &processctx.ProcessContext{UID: 1001, PID: 1234},
	})
	b := KeyFor(alert.Finding{
		Mailbox: "alice@example.com",
		Process: &processctx.ProcessContext{UID: 1002, PID: 5678},
	})
	if keyString(a) != keyString(b) {
		t.Fatalf("mailbox key split by process UID: a=%q b=%q", keyString(a), keyString(b))
	}
}

// TestKeyFor_ProcessUIDDoesNotSplitAccountKey: same for an
// account-keyed finding observed via different processes.
func TestKeyFor_ProcessUIDDoesNotSplitAccountKey(t *testing.T) {
	a := KeyFor(alert.Finding{
		TenantID: "alice",
		Process:  &processctx.ProcessContext{UID: 1001},
	})
	b := KeyFor(alert.Finding{
		TenantID: "alice",
		Process:  &processctx.ProcessContext{UID: 1002},
	})
	if keyString(a) != keyString(b) {
		t.Fatalf("account key split by process UID: a=%q b=%q", keyString(a), keyString(b))
	}
}

// TestKeyFor_ProcessUIDStillKeysWhenNoAccountOrMailbox: when no
// other actor is available, UID still serves as the primary key. We
// only drop UID as a "splitter" when stronger identifiers exist.
func TestKeyFor_ProcessUIDStillKeysWhenNoAccountOrMailbox(t *testing.T) {
	k := KeyFor(alert.Finding{
		Process: &processctx.ProcessContext{UID: 1001},
	})
	if k.UID != 1001 {
		t.Fatalf("UID-only key lost UID: %+v", k)
	}
}
