package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/privops"
)

// The command is what an operator runs before installing, so every row of the
// inventory has to reach the terminal, not just the ones with a config key.
func TestPrivilegesTextListsEveryOperation(t *testing.T) {
	var buf bytes.Buffer
	printPrivilegesText(&buf)
	out := buf.String()

	for _, op := range privops.Operations() {
		if !strings.Contains(out, op.ID) {
			t.Errorf("output omits operation %q", op.ID)
		}
	}
	if !strings.Contains(out, "OPERATION") {
		t.Error("output has no header row")
	}
}

func TestPrivilegesTextNamesTheWayOutOfEveryAutomaticHostChange(t *testing.T) {
	var buf bytes.Buffer
	printPrivilegesText(&buf)

	for _, line := range strings.Split(buf.String(), "\n") {
		for _, op := range privops.Operations() {
			if !strings.HasPrefix(line, op.ID+" ") || op.DisableKey == "" {
				continue
			}
			if !strings.Contains(line, op.DisableKey) {
				t.Errorf("row for %q does not name %q", op.ID, op.DisableKey)
			}
		}
	}
}
