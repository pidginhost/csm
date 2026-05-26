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

// TestKeyFor_ProcessUIDStillKeysWhenNoStableActor: when no
// other actor is available, UID still serves as the primary key. We
// only drop UID as a "splitter" when stronger identifiers exist.
func TestKeyFor_ProcessUIDStillKeysWhenNoStableActor(t *testing.T) {
	k := KeyFor(alert.Finding{
		Process: &processctx.ProcessContext{UID: 1001},
	})
	if k.UID != 1001 {
		t.Fatalf("UID-only key lost UID: %+v", k)
	}
}

func TestKeyFor_ProcessIdentityDoesNotSplitStableActorKeys(t *testing.T) {
	tests := []struct {
		name string
		a    alert.Finding
		b    alert.Finding
	}{
		{
			name: "domain drops uid",
			a: alert.Finding{
				Domain:  "example.com",
				Process: &processctx.ProcessContext{UID: 1001, PID: 1234},
			},
			b: alert.Finding{
				Domain:  "example.com",
				Process: &processctx.ProcessContext{UID: 1002, PID: 5678},
			},
		},
		{
			name: "domain drops pid",
			a: alert.Finding{
				Domain:  "example.com",
				Process: &processctx.ProcessContext{PID: 1234},
			},
			b: alert.Finding{
				Domain:  "example.com",
				Process: &processctx.ProcessContext{PID: 5678},
			},
		},
		{
			name: "cpuser drops uid",
			a: alert.Finding{
				CPUser:  "alice",
				Process: &processctx.ProcessContext{UID: 1001, PID: 1234},
			},
			b: alert.Finding{
				CPUser:  "alice",
				Process: &processctx.ProcessContext{UID: 1002, PID: 5678},
			},
		},
		{
			name: "cpuser drops pid",
			a: alert.Finding{
				CPUser:  "alice",
				Process: &processctx.ProcessContext{PID: 1234},
			},
			b: alert.Finding{
				CPUser:  "alice",
				Process: &processctx.ProcessContext{PID: 5678},
			},
		},
		{
			name: "home path drops uid",
			a: alert.Finding{
				FilePath: "/home/alice/public_html/shell.php",
				Process:  &processctx.ProcessContext{UID: 1001, PID: 1234},
			},
			b: alert.Finding{
				FilePath: "/home/alice/public_html/other.php",
				Process:  &processctx.ProcessContext{UID: 1002, PID: 5678},
			},
		},
		{
			name: "home path drops pid",
			a: alert.Finding{
				FilePath: "/home/alice/public_html/shell.php",
				Process:  &processctx.ProcessContext{PID: 1234},
			},
			b: alert.Finding{
				FilePath: "/home/alice/public_html/other.php",
				Process:  &processctx.ProcessContext{PID: 5678},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := KeyFor(tt.a)
			b := KeyFor(tt.b)
			if keyString(a) != keyString(b) {
				t.Fatalf("process identity split stable actor key: a=%q b=%q", keyString(a), keyString(b))
			}
			if a.UID != 0 || a.PID != 0 || b.UID != 0 || b.PID != 0 {
				t.Fatalf("process identity leaked into stable actor key: a=%+v b=%+v", a, b)
			}
		})
	}
}
