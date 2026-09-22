//go:build linux

package daemon

import "testing"

func overridePanelToolRoots(t *testing.T, roots []string) {
	t.Helper()
	old := panelToolRoots
	panelToolRoots = func() []string { return roots }
	t.Cleanup(func() { panelToolRoots = old })
}
