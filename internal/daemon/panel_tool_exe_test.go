package daemon

import (
	"os"
	"testing"
)

var cpanelRoots = []string{"/usr/local/cpanel"}

// Only a binary that no non-root user could have put in place counts as
// evidence that the panel's own maintenance ran. comm is settable by the
// process itself, which is why provenance reads the resolved exe instead.
func TestPanelToolExeTrusted(t *testing.T) {
	const rootOwned = 0
	const userOwned = 1000

	tests := []struct {
		name string
		exe  string
		mode os.FileMode
		uid  uint32
		want bool
	}{
		{name: "root-owned panel script", exe: "/usr/local/cpanel/scripts/upcp", mode: 0755, uid: rootOwned, want: true},
		{name: "root-owned panel binary deeper in the tree", exe: "/usr/local/cpanel/3rdparty/bin/perl", mode: 0755, uid: rootOwned, want: true},
		{name: "outside every panel root", exe: "/tmp/upcp", mode: 0755, uid: rootOwned, want: false},
		{name: "sibling directory sharing the root prefix", exe: "/usr/local/cpanelx/scripts/upcp", mode: 0755, uid: rootOwned, want: false},
		{name: "traversal back out of the root", exe: "/usr/local/cpanel/../../../tmp/upcp", mode: 0755, uid: rootOwned, want: false},
		{name: "owned by an unprivileged user", exe: "/usr/local/cpanel/scripts/upcp", mode: 0755, uid: userOwned, want: false},
		{name: "group writable", exe: "/usr/local/cpanel/scripts/upcp", mode: 0775, uid: rootOwned, want: false},
		{name: "world writable", exe: "/usr/local/cpanel/scripts/upcp", mode: 0757, uid: rootOwned, want: false},
		{name: "not a regular file", exe: "/usr/local/cpanel/scripts/upcp", mode: os.ModeSymlink | 0755, uid: rootOwned, want: false},
		{name: "binary unlinked after exec", exe: "/usr/local/cpanel/scripts/upcp (deleted)", mode: 0755, uid: rootOwned, want: false},
		{name: "relative path", exe: "usr/local/cpanel/scripts/upcp", mode: 0755, uid: rootOwned, want: false},
		{name: "the root itself", exe: "/usr/local/cpanel", mode: 0755, uid: rootOwned, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := panelToolExeTrusted(tt.exe, cpanelRoots, tt.mode, tt.uid); got != tt.want {
				t.Fatalf("panelToolExeTrusted(%q, %v, %d) = %v, want %v", tt.exe, tt.mode, tt.uid, got, tt.want)
			}
		})
	}
}

// A host with no panel has no tool root, so no exe can be trusted on this
// evidence and the check cannot be turned into a blanket demotion.
func TestPanelToolExeTrustedWithoutRootsIsFalse(t *testing.T) {
	if panelToolExeTrusted("/usr/local/cpanel/scripts/upcp", nil, 0755, 0) {
		t.Fatal("exe trusted with no configured panel roots")
	}
}
