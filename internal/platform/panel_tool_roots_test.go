package platform

import "testing"

// A cPanel host runs its own maintenance from /usr/local/cpanel. Provenance
// checks need that root from platform detection rather than hardcoding it.
func TestPanelToolRootsOnCPanel(t *testing.T) {
	roots := Info{Panel: PanelCPanel}.PanelToolRoots()
	if len(roots) != 1 || roots[0] != "/usr/local/cpanel" {
		t.Fatalf("cPanel tool roots = %v, want [/usr/local/cpanel]", roots)
	}
}

// A host with no panel has no vendor tool root, so nothing can be demoted on
// this evidence there.
func TestPanelToolRootsWithoutPanelIsEmpty(t *testing.T) {
	if roots := (Info{Panel: PanelNone}).PanelToolRoots(); len(roots) != 0 {
		t.Fatalf("panel-less tool roots = %v, want none", roots)
	}
}
