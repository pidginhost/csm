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

// The table is read in a terminal, so one operation that writes thirty paths
// must not pad every other row to that width. The full list stays available
// in --json.
func TestPrivilegesTextKeepsRowsReadable(t *testing.T) {
	var buf bytes.Buffer
	if err := printPrivilegesText(&buf); err != nil {
		t.Fatalf("print: %v", err)
	}
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "Operations with no config switch") {
			// The notes under the table carry sentences, not table columns.
			continue
		}
		// The budget is the four clamped columns plus the longest config key,
		// which is never truncated. Wide, but it fits a normal terminal and
		// every row is the same width.
		if width := len([]rune(line)); width > 165 {
			t.Fatalf("row is %d characters wide, too wide to read in a terminal:\n%s", width, line)
		}
	}
}

func TestSummarizeWritesElidesLongListsAndCountsTheRest(t *testing.T) {
	got := summarizeWrites([]string{"/etc/audit", "/var/cpanel", "/etc/nginx/conf.d", "/tmp", "/home"}, false)
	if !strings.Contains(got, "+3 more") {
		t.Fatalf("summary = %q, want the remaining count", got)
	}
	if !strings.Contains(got, "/etc/audit") {
		t.Fatalf("summary = %q, want the first paths kept", got)
	}
	if got := summarizeWrites(nil, false); got != "-" {
		t.Fatalf("read-only summary = %q, want -", got)
	}
	if got := summarizeWrites([]string{"exim:configuration"}, true); !strings.Contains(got, "unsandboxed") {
		t.Fatalf("summary = %q, want the unsandboxed marker", got)
	}
}

func TestClampCellMarksWhatItCut(t *testing.T) {
	if got := clampCell("short", 10); got != "short" {
		t.Fatalf("clamped a value that fits: %q", got)
	}
	got := clampCell("auto_response.virtual_patch_exposed_files: off", 20)
	if len([]rune(got)) != 20 {
		t.Fatalf("clamped to %d runes, want 20: %q", len([]rune(got)), got)
	}
	if !strings.HasSuffix(got, "\u2026") {
		t.Fatalf("clamped value does not mark the cut: %q", got)
	}
}
