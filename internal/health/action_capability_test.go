package health

import (
	"slices"
	"testing"
)

func TestActionShowCapability(t *testing.T) {
	if !slices.Contains(Capabilities(), "admission.action_show.v1") {
		t.Fatal("the read-only admission action command is not advertised")
	}
}
