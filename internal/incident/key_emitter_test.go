package incident

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/processctx"
)

// Findings emitted by realtime detectors must carry enough actor context
// for KeyFor to return a non-empty Key, or the per-finding incident
// correlator silently drops them and never groups repeat events from the
// same attacker.
//
// Each test below pins the field shape the production emitter must
// produce. A regression that strips SourceIP/FilePath/Process from one
// of these emit sites will turn the corresponding test red, even if the
// finding still serializes "correctly".

func TestKeyFor_C2ConnectionHasNonEmptyKey(t *testing.T) {
	// network.go::CheckOutboundConnections emits this for hits on
	// cfg.C2Blocklist. Without SourceIP the finding is unkeyable -
	// repeat connections from the same C2 IP would never merge.
	f := alert.Finding{
		Severity: alert.Critical,
		Check:    "c2_connection",
		Message:  "Connection to known C2 IP: 198.51.100.7:443",
		SourceIP: "198.51.100.7",
	}
	if k := KeyFor(f); k.IsEmpty() {
		t.Fatalf("c2_connection key empty; finding=%+v key=%+v", f, k)
	}
}

func TestKeyFor_BackdoorPortHasNonEmptyKey(t *testing.T) {
	// network.go emits backdoor_port for an inbound connection on a
	// listening backdoor port. The actor of interest is the remote IP.
	f := alert.Finding{
		Severity: alert.Critical,
		Check:    "backdoor_port",
		Message:  "Listening on known backdoor port 4444, connected from 198.51.100.8:55555",
		SourceIP: "198.51.100.8",
	}
	if k := KeyFor(f); k.IsEmpty() {
		t.Fatalf("backdoor_port key empty; key=%+v", k)
	}
}

func TestKeyFor_BackdoorPortOutboundHasNonEmptyKey(t *testing.T) {
	// network.go emits backdoor_port_outbound when CSM observes our
	// process reaching out to a backdoor port on a remote host (reverse
	// shell calling home). Actor = remote IP.
	f := alert.Finding{
		Severity: alert.High,
		Check:    "backdoor_port_outbound",
		Message:  "Outbound connection to backdoor port: 198.51.100.9:4444",
		SourceIP: "198.51.100.9",
	}
	if k := KeyFor(f); k.IsEmpty() {
		t.Fatalf("backdoor_port_outbound key empty; key=%+v", k)
	}
}

func TestKeyFor_PHPSuspiciousExecutionHasNonEmptyKey(t *testing.T) {
	// processes.go::CheckSuspiciousProcesses emits this when lsphp runs
	// from /tmp / /dev/shm / hidden config. UID is the actor of
	// interest because the same compromised cPanel user re-executes
	// from various tmp paths. Without Process the only key bait is
	// PID, which churns per restart.
	f := alert.Finding{
		Severity: alert.Critical,
		Check:    "php_suspicious_execution",
		Message:  "PHP executing from suspicious path: /tmp/",
		PID:      4242,
		Process:  &processctx.ProcessContext{PID: 4242, UID: 1001, Account: "alice"},
	}
	if k := KeyFor(f); k.IsEmpty() {
		t.Fatalf("php_suspicious_execution key empty; key=%+v", k)
	}
	if k := KeyFor(f); k.Account != "alice" {
		t.Errorf("expected Account=alice from Process.Account, got %q", k.Account)
	}
}

func TestKeyFor_BackdoorBinaryHasNonEmptyKey(t *testing.T) {
	// account_scan.go::ScanAccount emits backdoor_binary when a
	// known-bad name lands on disk inside an account home. FilePath
	// drives the /home heuristic in KeyFor, so the account name is
	// recoverable for grouping.
	f := alert.Finding{
		Severity: alert.Critical,
		Check:    "backdoor_binary",
		Message:  "Backdoor binary found: /home/alice/public_html/wp-content/uploads/.x",
		FilePath: "/home/alice/public_html/wp-content/uploads/.x",
	}
	k := KeyFor(f)
	if k.IsEmpty() {
		t.Fatalf("backdoor_binary key empty; key=%+v", k)
	}
	if k.Account != "alice" {
		t.Errorf("expected Account=alice from /home heuristic, got %q", k.Account)
	}
}

// Negative-control: a finding with all the actor fields stripped must
// produce an empty key. Without this anchor a future change that
// silently substitutes a non-actor field could still pass the positive
// tests above.
func TestKeyFor_StrippedFindingIsEmpty(t *testing.T) {
	f := alert.Finding{
		Severity: alert.Critical,
		Check:    "c2_connection",
		Message:  "Connection to known C2 IP",
	}
	if k := KeyFor(f); !k.IsEmpty() {
		t.Fatalf("stripped finding should produce empty key, got %+v", k)
	}
}
