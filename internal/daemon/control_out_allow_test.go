package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

func TestFmtOutAllowRendersDestinationAndRange(t *testing.T) {
	got := fmtOutAllow([]firewall.OutAllowRule{
		{Dst: "203.0.113.155/32", PortStart: 49152, PortEnd: 65534},
		{Dst: "0.0.0.0/0", PortStart: 9090, PortEnd: 9090},
	})
	want := []string{
		"203.0.113.155/32 tcp 49152-65534",
		"0.0.0.0/0 tcp 9090",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d lines %v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// An operator reading `csm firewall status` must be able to tell "no
// destination-scoped egress" from "some, not shown".
func TestFmtOutAllowEmptyRendersNothing(t *testing.T) {
	if got := fmtOutAllow(nil); len(got) != 0 {
		t.Errorf("got %v, want no lines", got)
	}
}
