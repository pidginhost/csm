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
	const (
		panelReason = "control panel maintenance ancestry"
		pkgReason   = "package manager ancestry during active package window"
	)
	tests := []struct {
		name       string
		window     bool
		roots      []string
		evidence   ancestryEvidence
		wantWalks  int
		wantReason string
	}{
		{
			name:     "no window and no panel roots",
			evidence: ancestryEvidence{packageManager: true},
		},
		{
			name:     "no window and empty panel roots",
			roots:    []string{},
			evidence: ancestryEvidence{packageManager: true},
		},
		{
			name: "panel tool without package window", roots: cpanelRoots,
			evidence: ancestryEvidence{panelTool: true}, wantWalks: 1, wantReason: panelReason,
		},
		{
			name: "package manager without panel roots", window: true,
			evidence: ancestryEvidence{packageManager: true}, wantWalks: 1, wantReason: pkgReason,
		},
		{
			name: "package manager on panel host", window: true, roots: cpanelRoots,
			evidence: ancestryEvidence{packageManager: true}, wantWalks: 1, wantReason: pkgReason,
		},
		{
			name: "package manager without window on panel host", roots: cpanelRoots,
			evidence: ancestryEvidence{packageManager: true}, wantWalks: 1,
		},
		{
			name: "panel evidence takes precedence", window: true, roots: cpanelRoots,
			evidence: ancestryEvidence{packageManager: true, panelTool: true}, wantWalks: 1, wantReason: panelReason,
		},
		{
			name: "package window without evidence", window: true, wantWalks: 1,
		},
		{
			name: "panel roots without evidence", roots: cpanelRoots, wantWalks: 1,
		},
		{
			name: "both gates without evidence", window: true, roots: cpanelRoots, wantWalks: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldW, oldA, oldR := tmpExecPkgWindow, tmpExecAncestry, panelToolRoots
			t.Cleanup(func() { tmpExecPkgWindow, tmpExecAncestry, panelToolRoots = oldW, oldA, oldR })
			now := time.Unix(1_700_000_000, 0)
			windowCalls, rootCalls, walked := 0, 0, 0
			tmpExecPkgWindow = func(got time.Time) bool {
				windowCalls++
				if !got.Equal(now) {
					t.Fatalf("package window time = %v, want %v", got, now)
				}
				return tt.window
			}
			panelToolRoots = func() []string {
				rootCalls++
				return tt.roots
			}
			tmpExecAncestry = func(pid int32) ancestryEvidence {
				walked++
				if pid != 4242 {
					t.Fatalf("ancestry pid = %d, want 4242", pid)
				}
				if windowCalls != 1 || rootCalls != 1 {
					t.Fatalf("ancestry ran before both cheap gates: window=%d roots=%d", windowCalls, rootCalls)
				}
				return tt.evidence
			}

			ok, reason := demoteTmpExec(0, 4242, now)
			if ok != (tt.wantReason != "") || reason != tt.wantReason {
				t.Fatalf("demoteTmpExec = (%v, %q), want (%v, %q)", ok, reason, tt.wantReason != "", tt.wantReason)
			}
			if walked != tt.wantWalks {
				t.Fatalf("ancestry walked %d times, want %d", walked, tt.wantWalks)
			}
			if windowCalls != 1 || rootCalls != 1 {
				t.Fatalf("cheap gate calls: window=%d roots=%d, want one each", windowCalls, rootCalls)
			}
		})
	}
}
