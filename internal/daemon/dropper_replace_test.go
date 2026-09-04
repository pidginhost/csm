package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A newer file at the path does not prove an atomic update: a dropper can
// execute, unlink itself, and rename a benign successor over the same path.
// Keep the candidate suspect because birth time cannot distinguish the two.
func TestAssessDropperInPlaceReplacementRemainsSuspect(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := freshDropperCandidate(now)
	successor := &dropperFileState{
		Path:       c.Path,
		Device:     c.Device,
		Inode:      c.Inode + 1,
		Size:       c.Size + 2,
		Birth:      now.Add(90 * time.Second),
		BirthKnown: true,
	}
	if got := assessDropper(c, dropperProbe{Conclusive: true, AtPath: successor}); got != dropperSuspect {
		t.Errorf("assessDropper() = %v, want dropperSuspect", got)
	}
}

// Filesystems may reuse the same inode number at the same path within the TTL.
// A changed birth time proves that this is not the tracked survivor, and must
// not convert the disappearance into a lower-severity replacement finding.
func TestAssessDropperReusedInodeRemainsSuspect(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := freshDropperCandidate(now)
	successor := &dropperFileState{
		Path:       c.Path,
		Device:     c.Device,
		Inode:      c.Inode,
		Birth:      c.Birth.Add(time.Minute),
		BirthKnown: true,
	}
	if got := assessDropper(c, dropperProbe{Conclusive: true, AtPath: successor}); got != dropperSuspect {
		t.Errorf("assessDropper() = %v, want dropperSuspect", got)
	}
}

func TestAssessDropperReplacementCannotFallThroughToTemplateDemotion(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := freshDropperCandidate(now)
	c.Head = []byte("<?php\nclass __TwigTemplate_ab12 extends Template {")
	successor := &dropperFileState{
		Path: c.Path, Device: c.Device, Inode: c.Inode + 1,
		Birth: now.Add(time.Minute), BirthKnown: true,
	}
	if got := assessDropper(c, dropperProbe{Conclusive: true, AtPath: successor}); got != dropperSuspect {
		t.Errorf("assessDropper() = %v, want dropperSuspect before template demotion", got)
	}
}

// A candidate whose whole parent directory is gone was not deleted on its own.
// WP Toolkit stages a full site copy under .wp-toolkit_c and removes the tree.
func TestAssessDropperParentDirectoryRemovedDemoted(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := freshDropperCandidate(now)
	if got := assessDropper(c, dropperProbe{Conclusive: true, ParentRemoved: true}); got != dropperDemotedDirRemoved {
		t.Errorf("assessDropper() = %v, want dropperDemotedDirRemoved", got)
	}
}

func TestAssessDropperParentDirectoryRemovedContentSignalWins(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := freshDropperCandidate(now)
	c.ContentSuspicious = true
	if got := assessDropper(c, dropperProbe{Conclusive: true, ParentRemoved: true}); got != dropperSuspect {
		t.Errorf("assessDropper() = %v, want dropperSuspect", got)
	}
}

func TestDropperVerdictDemotedCoversDirectoryRemoval(t *testing.T) {
	if !dropperVerdictDemoted(dropperDemotedDirRemoved) {
		t.Error("dropperVerdictDemoted(dropperDemotedDirRemoved) = false, want true")
	}
	if dropperVerdictDemoted(dropperSuspect) {
		t.Error("dropperVerdictDemoted(dropperSuspect) = true, want false")
	}
}

func TestDropperAlertParamsExplainsDirectoryRemoval(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	f := dropperFinding{
		Docroot: "/home/alice/public_html",
		Items:   []dropperGone{{Cand: freshDropperCandidate(now), Verdict: dropperDemotedDirRemoved}},
	}
	sev, _, details, _ := dropperAlertParams(f)
	if sev != alert.Warning {
		t.Errorf("severity = %v, want Warning", sev)
	}
	if want := "original containing directory was removed"; !strings.Contains(details, want) {
		t.Errorf("details = %q, want it to mention %q", details, want)
	}
}
