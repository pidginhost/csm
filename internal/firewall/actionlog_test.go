package firewall

import (
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
)

type recordingSink struct {
	mu      sync.Mutex
	records []actionlog.Record
}

func (r *recordingSink) Write(rec actionlog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec)
	return nil
}

func withActionSink(t *testing.T) *recordingSink {
	t.Helper()
	sink := &recordingSink{}
	actionlog.SetSink(sink, "host.example.com")
	t.Cleanup(func() { actionlog.SetSink(nil, "") })
	return sink
}

// Firewall changes were recorded in their own log and nowhere else, so an
// operator reviewing "what did CSM do" had to read one file per subsystem.
// Every entry now also lands on the unified stream, tagged with the
// privileged operation it belongs to and with who asked for it.
func TestFirewallAuditAlsoRecordsAnAction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
		reason string
		op     string
		actor  actionlog.Actor
	}{
		{"auto block", SourceAutoResponse, "auto-block: ssh brute force", "respond.block_ip", actionlog.Daemon},
		{"operator cli", SourceCLI, "manual block via cli", "operate.manual_firewall", actionlog.CLI},
		{"operator web ui", SourceWebUI, "manual block via csm web ui", "operate.manual_firewall", actionlog.WebUI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := withActionSink(t)
			AppendAudit(t.TempDir(), "block", "192.0.2.10", tc.reason, tc.source, 30*time.Minute)

			if len(sink.records) != 1 {
				t.Fatalf("records = %d, want 1", len(sink.records))
			}
			got := sink.records[0]
			if got.Op != tc.op {
				t.Errorf("op = %q, want %q", got.Op, tc.op)
			}
			if got.Actor != tc.actor {
				t.Errorf("actor = %q, want %q", got.Actor, tc.actor)
			}
			if got.Target != "192.0.2.10" {
				t.Errorf("target = %q, want the address", got.Target)
			}
			if got.Reason != tc.reason {
				t.Errorf("reason = %q, want %q", got.Reason, tc.reason)
			}
			if got.Result != actionlog.Applied {
				t.Errorf("result = %q, want applied", got.Result)
			}
		})
	}
}

func TestFirewallBlockDoesNotSuggestAnAllowlistAsUndo(t *testing.T) {
	sink := withActionSink(t)
	AppendAudit(t.TempDir(), "block", "198.51.100.4", "auto-block: mail brute force", SourceAutoResponse, 0)

	if len(sink.records) != 1 {
		t.Fatalf("records = %d, want 1", len(sink.records))
	}
	if got := sink.records[0].Undo; got != "" {
		t.Fatalf("undo = %q, cannot undo a block by creating a permanent allow", got)
	}
}

func TestFirewallFlushRecordsTheManualOperation(t *testing.T) {
	sink := withActionSink(t)
	AppendAudit(t.TempDir(), "flush", "", "operator flush", "", 0)

	if len(sink.records) != 1 {
		t.Fatalf("records = %d, want 1", len(sink.records))
	}
	if got := sink.records[0].Op; got != "operate.manual_firewall" {
		t.Fatalf("op = %q, want operate.manual_firewall", got)
	}
}
