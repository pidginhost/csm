package main

import (
	"testing"

	"github.com/pidginhost/csm/internal/actionlog"
)

// The action-show fast path must not bypass the summary-only cause check,
// either while reading input or while verifying the exported row.
func TestActionShowRejectsAttributionCauses(t *testing.T) {
	for _, cause := range []string{"kind_not_allowed", "target 192.0.2.9"} {
		t.Run(cause, func(t *testing.T) {
			a := NewAnonymizer(testSalt())
			r := actionlog.Record{V: actionlog.SchemaVersion, Timestamp: recordTS,
				Op: "respond.block_ip", Action: "show", Actor: actionlog.CLI,
				ActorDetail: "csm action show", Target: "cand_11111111111111111111111111111111", Result: "read"}
			out, err := a.Action(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := a.VerifyAction(out); err != nil {
				t.Fatalf("valid inspection row: %v", err)
			}
			r.Cause = cause
			if _, err := a.Action(r); err == nil {
				t.Error("an inspection row accepted a summary-only cause")
			}
			out.Cause = cause
			if err := a.VerifyAction(out); err == nil {
				t.Error("an inspection row verified an unvalidated cause")
			}
		})
	}
}
