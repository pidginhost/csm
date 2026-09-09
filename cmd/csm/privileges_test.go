package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/privops"
)

func TestPrivilegesReportsOutputFailure(t *testing.T) {
	if format := os.Getenv("CSM_TEST_PRIVILEGES_OUTPUT_FAILURE"); format != "" {
		os.Args = []string{"csm", "privileges", "--" + format}
		if err := os.Stdout.Close(); err != nil {
			panic(err)
		}
		runPrivileges()
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"text", "json", "markdown"} {
		t.Run(format, func(t *testing.T) {
			cmd := exec.Command(executable, "-test.run=^TestPrivilegesReportsOutputFailure$")
			cmd.Env = append(os.Environ(), "CSM_TEST_PRIVILEGES_OUTPUT_FAILURE="+format)
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("command succeeded with a closed stdout: %s", output)
			}
			if !strings.Contains(string(output), "privileged-operation inventory") {
				t.Errorf("missing inventory output error: %s", output)
			}
		})
	}
}

// The command is what an operator runs before installing, so every row of the
// inventory has to reach the terminal, not just the ones with a config key.
func TestPrivilegesTextListsEveryOperation(t *testing.T) {
	var buf bytes.Buffer
	if err := printPrivilegesText(&buf); err != nil {
		t.Fatal(err)
	}
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
	if err := printPrivilegesText(&buf); err != nil {
		t.Fatal(err)
	}

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

func TestPrivilegesTextDisclosesMissingSwitches(t *testing.T) {
	var buf bytes.Buffer
	if err := printPrivilegesText(&buf); err != nil {
		t.Fatal(err)
	}
	for _, op := range privops.Operations() {
		if op.DisableReason != "" && !strings.Contains(buf.String(), op.DisableInstruction()) {
			t.Errorf("%s omits why it cannot be disabled", op.ID)
		}
	}
}
