package webui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every confirm for an action that deletes data, blocks traffic, turns
// protection off or discards work names the action on a red button that
// does not hold the focus. ui/confirm_test.js drives the dialog itself.
func TestDestructiveConfirmsAreMarkedDanger(t *testing.T) {
	files, err := filepath.Glob("../../ui/static/js/*.js")
	if err != nil {
		t.Fatal(err)
	}
	destructive := regexp.MustCompile(`CSM\.confirm\((["'])(Permanently delete|Delete|Block|Disable|Remove all |Permanently whitelist|You have unsaved changes)`)
	var checked int
	for _, file := range files {
		if strings.HasSuffix(file, ".min.js") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for n, line := range strings.Split(string(src), "\n") {
			if !destructive.MatchString(line) {
				continue
			}
			checked++
			if !strings.Contains(line, "danger: true") || !strings.Contains(line, "okLabel: ") {
				t.Errorf("%s:%d: destructive confirm without danger styling: %s", filepath.Base(file), n+1, strings.TrimSpace(line))
			}
		}
	}
	// The floor is the number of call sites today (Cleanup History's copy of
	// the file backup delete went with its duplicate list). Lower it only
	// when a destructive confirm is removed, never to let the pattern miss.
	if checked < 14 {
		t.Fatalf("matched only %d destructive confirms; the pattern no longer finds the call sites", checked)
	}

	// Confirms whose text is built in a variable.
	for _, tc := range []struct{ file, fragment string }{
		{"threat.js", "return CSM.confirm(question, { danger: true, okLabel: 'Block' })"},
		{"firewall.js", "CSM.confirm(confirmMsg, { danger: permanent, okLabel: permanent ? 'Whitelist' : 'OK' })"},
	} {
		if !strings.Contains(readUIScript(t, tc.file), tc.fragment) {
			t.Errorf("%s missing danger confirm %q", tc.file, tc.fragment)
		}
	}
}
