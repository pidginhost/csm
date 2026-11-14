//go:build linux

package daemon

import (
	"testing"
	"time"
)

// The decision runs for every root-owned executable written under a temp root.
// It reads each gate once, never walks the process chain itself, and evidence
// must not demote without the gate that corroborates it.
func TestDemoteTmpExecReadsEachGateOnce(t *testing.T) {
	const (
		panelReason     = "control panel maintenance ancestry"
		pkgReason       = "package manager ancestry during active package window"
		initramfsReason = "initramfs build ancestry"
	)
	tests := []struct {
		name       string
		window     bool
		roots      []string
		evidence   ancestryEvidence
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
			name:     "panel evidence without panel roots",
			evidence: ancestryEvidence{panelTool: true},
		},
		{
			name:     "initramfs builder without window or panel roots",
			evidence: ancestryEvidence{initramfsBuilder: true}, wantReason: initramfsReason,
		},
		{
			name: "package reason precedes initramfs builder", window: true,
			evidence: ancestryEvidence{packageManager: true, initramfsBuilder: true}, wantReason: pkgReason,
		},
		{
			name: "panel tool without package window", roots: cpanelRoots,
			evidence: ancestryEvidence{panelTool: true}, wantReason: panelReason,
		},
		{
			name: "package manager without panel roots", window: true,
			evidence: ancestryEvidence{packageManager: true}, wantReason: pkgReason,
		},
		{
			name: "package manager on panel host", window: true, roots: cpanelRoots,
			evidence: ancestryEvidence{packageManager: true}, wantReason: pkgReason,
		},
		{
			name: "package manager without window on panel host", roots: cpanelRoots,
			evidence: ancestryEvidence{packageManager: true},
		},
		{
			name: "panel evidence takes precedence", window: true, roots: cpanelRoots,
			evidence: ancestryEvidence{packageManager: true, panelTool: true}, wantReason: panelReason,
		},
		{
			name: "package window without evidence", window: true,
		},
		{
			name: "panel roots without evidence", roots: cpanelRoots,
		},
		{
			name: "both gates without evidence", window: true, roots: cpanelRoots,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldW, oldA, oldR := tmpExecPkgWindow, tmpExecAncestry, panelToolRoots
			t.Cleanup(func() { tmpExecPkgWindow, tmpExecAncestry, panelToolRoots = oldW, oldA, oldR })
			now := time.Unix(1_700_000_000, 0)
			windowCalls, rootCalls := 0, 0
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
			tmpExecAncestry = func(int32) ancestryEvidence {
				t.Fatal("the decision walked: its evidence is read when the event is admitted")
				return ancestryEvidence{}
			}

			ok, reason := demoteTmpExec(0, tt.evidence, now)
			if ok != (tt.wantReason != "") || reason != tt.wantReason {
				t.Fatalf("demoteTmpExec = (%v, %q), want (%v, %q)", ok, reason, tt.wantReason != "", tt.wantReason)
			}
			if windowCalls != 1 || rootCalls != 1 {
				t.Fatalf("cheap gate calls: window=%d roots=%d, want one each", windowCalls, rootCalls)
			}
		})
	}
}

// The ancestry is read once per event: at admission when the writer is most
// likely still running, else when the event is analyzed. A file that is not
// root-owned, or has no writer, is never walked.
func TestTmpExecEvidenceWalksAtMostOnce(t *testing.T) {
	captured := ancestryEvidence{panelTool: true}
	walked := ancestryEvidence{packageManager: true}
	for _, tt := range []struct {
		name      string
		event     fileEvent
		uid       uint32
		want      ancestryEvidence
		wantWalks int
	}{
		{"captured at admission", fileEvent{pid: 4242, tmpAncestry: &captured}, 0, captured, 0},
		{"not captured", fileEvent{pid: 4242}, 0, walked, 1},
		{"not root-owned", fileEvent{pid: 4242}, 1000, ancestryEvidence{}, 0},
		{"no writer", fileEvent{}, 0, ancestryEvidence{}, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			old := tmpExecAncestry
			t.Cleanup(func() { tmpExecAncestry = old })
			walks := 0
			tmpExecAncestry = func(pid int32) ancestryEvidence {
				walks++
				if pid != 4242 {
					t.Fatalf("ancestry pid = %d, want 4242", pid)
				}
				return walked
			}
			if got := tmpExecEvidence(tt.event, tt.uid); got != tt.want || walks != tt.wantWalks {
				t.Fatalf("tmpExecEvidence = %+v after %d walks, want %+v after %d", got, walks, tt.want, tt.wantWalks)
			}
		})
	}
}
