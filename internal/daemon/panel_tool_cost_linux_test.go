//go:build linux

package daemon

import (
	"testing"
	"time"
)

// The ancestry walk costs up to maxAncestryDepth procfs reads per event, and
// it runs for every root-owned executable written under a temp root. When
// neither arm can demote -- no package transaction in the window and no panel
// tool root to match an exe against -- the walk cannot change the verdict, so
// it must not run at all.
func TestDemoteTmpExecSkipsWalkWhenNothingCanDemote(t *testing.T) {
	walked := 0
	oldW, oldA, oldR := tmpExecPkgWindow, tmpExecAncestry, panelToolRoots
	tmpExecAncestry = func(int32) ancestryEvidence {
		walked++
		return ancestryEvidence{packageManager: true, panelTool: true}
	}
	t.Cleanup(func() { tmpExecPkgWindow, tmpExecAncestry, panelToolRoots = oldW, oldA, oldR })

	t.Run("no window and no panel roots", func(t *testing.T) {
		walked = 0
		tmpExecPkgWindow = func(time.Time) bool { return false }
		panelToolRoots = func() []string { return nil }

		if ok, _ := demoteTmpExec(0, 4242, time.Now()); ok {
			t.Fatal("nothing could demote, yet the finding was demoted")
		}
		if walked != 0 {
			t.Fatalf("ancestry walked %d times, want 0", walked)
		}
	})

	t.Run("panel roots present still walks", func(t *testing.T) {
		walked = 0
		tmpExecPkgWindow = func(time.Time) bool { return false }
		panelToolRoots = func() []string { return []string{"/usr/local/cpanel"} }

		if ok, _ := demoteTmpExec(0, 4242, time.Now()); !ok {
			t.Fatal("panel-tool ancestry must still demote without a package window")
		}
		if walked != 1 {
			t.Fatalf("ancestry walked %d times, want 1", walked)
		}
	})

	t.Run("package window present still walks", func(t *testing.T) {
		walked = 0
		tmpExecPkgWindow = func(time.Time) bool { return true }
		panelToolRoots = func() []string { return nil }

		if ok, _ := demoteTmpExec(0, 4242, time.Now()); !ok {
			t.Fatal("package-manager ancestry in an active window must demote")
		}
		if walked != 1 {
			t.Fatalf("ancestry walked %d times, want 1", walked)
		}
	})
}
