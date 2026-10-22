//go:build linux && nftkernel

package store

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

// Undoing one member removes only its element; the batch's other member and
// a later block stay, and the whole batch can no longer be undone.
func TestKernelDurableMemberUndoLeavesOtherMembers(t *testing.T) {
	_, e, d := durableKernelEngine(t)
	header := firewall.ActionRequest{ID: "batch-undo", Operation: "block", Actor: "auto", Source: "scan", Automatic: true}
	result, err := e.BlockBatchRequest(header, []firewall.ActionRequest{kernelBatchMember("member-a", "203.0.113.70"), kernelBatchMember("member-b", "2001:db8::70")}, nil)
	if err != nil || result.Action.Phase != "verified" {
		t.Fatalf("batch = %s, %v", result.Action.Phase, err)
	}
	if _, err := d.BlockIPRequest(firewall.ActionRequest{ID: "operator", Target: "198.51.100.70", Reason: "operator", Actor: "cli", Source: "cli"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UndoAction(firewall.ActionRequest{ID: "undo-member-a", Operation: "undo", Actor: "cli", Source: "cli", UndoOf: "member-a"}); err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]bool{"203.0.113.70": false, "2001:db8::70": true, "198.51.100.70": true} {
		if _, live := kernelElement(t, ip); live != want {
			t.Errorf("%s in the kernel = %v, want %v", ip, live, want)
		}
	}
	if _, err := d.UndoAction(firewall.ActionRequest{ID: "undo-batch", Operation: "undo", Actor: "cli", Source: "cli", UndoOf: header.ID}); !errors.Is(err, firewall.ErrStateConflict) {
		t.Fatalf("batch undo after a member undo = %v", err)
	}
}
