package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A file whose path is taken over by a newer inode was replaced, not deleted.
// Wordfence rewrites wflogs/*.php over the live path every few minutes, which
// is indistinguishable from a self-delete on identity alone.
func TestAssessDropperInPlaceReplacementDemoted(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := freshDropperCandidate(now)
	successor := &dropperFileState{
		Path:       c.Path,
		Device:     c.Device,
		Inode:      c.Inode + 1,
		Size:       c.Size + 2,
		Birth:      now.Add(90 * time.Second),
		BirthKnown: true,
		IsRegular:  true,
	}
	if got := assessDropper(c, dropperProbe{Conclusive: true, AtPath: successor}); got != dropperDemotedReplaced {
		t.Errorf("assessDropper() = %v, want dropperDemotedReplaced", got)
	}
}

// A freed inode number is routinely handed straight back to the next file at
// the same path (observed live on ext4 under Wordfence). The changed birth
// time proves this is a successor rather than the tracked file, and it is
// still a replacement, not a disappearance.
func TestAssessDropperReusedInodeAtSamePathDemoted(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := freshDropperCandidate(now)
	successor := &dropperFileState{
		Path:       c.Path,
		Device:     c.Device,
		Inode:      c.Inode,
		Birth:      now.Add(time.Minute),
		BirthKnown: true,
		IsRegular:  true,
	}
	if got := assessDropper(c, dropperProbe{Conclusive: true, AtPath: successor}); got != dropperDemotedReplaced {
		t.Errorf("assessDropper() = %v, want dropperDemotedReplaced", got)
	}
}

// A successor born before the candidate was observed is not the completion of
// an atomic write: something moved an older file over the path.
func TestAssessDropperInPlaceReplacementRequiresNewerBirth(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := freshDropperCandidate(now)
	successor := &dropperFileState{
		Path:       c.Path,
		Device:     c.Device,
		Inode:      c.Inode + 1,
		Birth:      now.Add(-time.Hour),
		BirthKnown: true,
		IsRegular:  true,
	}
	if got := assessDropper(c, dropperProbe{Conclusive: true, AtPath: successor}); got != dropperSuspect {
		t.Errorf("assessDropper() = %v, want dropperSuspect", got)
	}
}

// Without a birth time the successor cannot be proven newer, and a directory
// or symlink at the path is not an atomic-write result either.
func TestAssessDropperInPlaceReplacementFailsClosed(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := freshDropperCandidate(now)
	cases := []struct {
		name string
		st   dropperFileState
	}{
		{"birth unknown", dropperFileState{Path: c.Path, Device: c.Device, Inode: c.Inode + 1, IsRegular: true}},
		{"not a regular file", dropperFileState{
			Path: c.Path, Device: c.Device, Inode: c.Inode + 1,
			Birth: now.Add(time.Minute), BirthKnown: true,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := tc.st
			if got := assessDropper(c, dropperProbe{Conclusive: true, AtPath: &st}); got != dropperSuspect {
				t.Errorf("assessDropper() = %v, want dropperSuspect", got)
			}
		})
	}
}

func TestAssessDropperInPlaceReplacementContentSignalWins(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := freshDropperCandidate(now)
	c.ContentSuspicious = true
	successor := &dropperFileState{
		Path: c.Path, Device: c.Device, Inode: c.Inode + 1,
		Birth: now.Add(time.Minute), BirthKnown: true, IsRegular: true,
	}
	if got := assessDropper(c, dropperProbe{Conclusive: true, AtPath: successor}); got != dropperSuspect {
		t.Errorf("assessDropper() = %v, want dropperSuspect", got)
	}
}

// A replaced path must be explained as a replacement, never mislabelled as a
// template compile artifact by a later heuristic.
func TestAssessDropperReplacementDemotionPrecedesTemplate(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := freshDropperCandidate(now)
	c.Head = []byte("<?php\nclass __TwigTemplate_ab12 extends Template {")
	successor := &dropperFileState{
		Path: c.Path, Device: c.Device, Inode: c.Inode + 1,
		Birth: now.Add(time.Minute), BirthKnown: true, IsRegular: true,
	}
	if got := assessDropper(c, dropperProbe{Conclusive: true, AtPath: successor}); got != dropperDemotedReplaced {
		t.Errorf("assessDropper() = %v, want dropperDemotedReplaced", got)
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

func TestDropperVerdictDemotedCoversNewVerdicts(t *testing.T) {
	for _, v := range []dropperVerdict{dropperDemotedDirRemoved, dropperDemotedReplaced} {
		if !dropperVerdictDemoted(v) {
			t.Errorf("dropperVerdictDemoted(%v) = false, want true", v)
		}
	}
	if dropperVerdictDemoted(dropperSuspect) {
		t.Error("dropperVerdictDemoted(dropperSuspect) = true, want false")
	}
}

func TestDropperAlertParamsExplainsNewDemotions(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	cases := []struct {
		verdict dropperVerdict
		want    string
	}{
		{dropperDemotedReplaced, "replaced in place"},
		{dropperDemotedDirRemoved, "original containing directory was removed"},
	}
	for _, tc := range cases {
		f := dropperFinding{
			Docroot: "/home/alice/public_html",
			Items:   []dropperGone{{Cand: freshDropperCandidate(now), Verdict: tc.verdict}},
		}
		sev, _, details, _ := dropperAlertParams(f)
		if sev != alert.Warning {
			t.Errorf("severity for %v = %v, want Warning", tc.verdict, sev)
		}
		if !strings.Contains(details, tc.want) {
			t.Errorf("details for %v = %q, want it to mention %q", tc.verdict, details, tc.want)
		}
	}
}
