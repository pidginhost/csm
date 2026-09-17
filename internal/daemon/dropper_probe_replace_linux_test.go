//go:build linux

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// End-to-end replacement: the probe must report a regular successor with a
// birth time so assessDropper can tell an atomic rewrite from a self-delete.
func TestDropperProbeDemotesSuccessorCreatedAfterObservation(t *testing.T) {
	docroot := t.TempDir()
	path := filepath.Join(docroot, "config-synced.php")
	c := freshDropperCandidate(time.Now().Add(-time.Minute))
	c.Docroot = docroot
	c.Path = path
	c.Inode = 1 // deliberately not the on-disk inode: the path was taken over

	if err := os.WriteFile(path, []byte("<?php exit('Access denied'); __halt_compiler(); ?>\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := dropperFSProbe{}.probe(c)
	if !p.Conclusive || p.AtPath == nil {
		t.Fatalf("probe = %+v, want a conclusive result with AtPath set", p)
	}
	if !p.AtPath.IsRegular {
		t.Error("AtPath.IsRegular = false, want true for a regular file")
	}
	if !p.AtPath.BirthKnown {
		t.Skip("filesystem does not report STATX_BTIME")
	}
	if got := assessDropper(c, p); got != dropperDemotedReplaced {
		t.Errorf("assessDropper() = %v, want dropperDemotedReplaced", got)
	}
}

// A file that was already at the path before the candidate was observed is not
// the completion of an atomic write, so it earns no demotion.
func TestDropperProbeKeepsOlderSuccessorAtPathSuspect(t *testing.T) {
	docroot := t.TempDir()
	path := filepath.Join(docroot, "config-synced.php")
	if err := os.WriteFile(path, []byte("<?php exit('Access denied'); __halt_compiler(); ?>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := freshDropperCandidate(time.Now().Add(time.Minute))
	c.Docroot = docroot
	c.Path = path
	c.Inode = 1

	p := dropperFSProbe{}.probe(c)
	if !p.Conclusive || p.AtPath == nil {
		t.Fatalf("probe = %+v, want a conclusive result with AtPath set", p)
	}
	if got := assessDropper(c, p); got != dropperSuspect {
		t.Errorf("assessDropper() = %v, want dropperSuspect for a pre-existing successor", got)
	}
}

func TestDropperProbeReportsRemovedParentDirectory(t *testing.T) {
	docroot := t.TempDir()
	staging := filepath.Join(docroot, ".wp-toolkit_c", "wp-content", "wflogs")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	c := freshDropperCandidate(time.Now())
	c.Docroot = docroot
	c.Path = filepath.Join(staging, "config-synced.php")
	parent, err := statDropperParent(staging)
	if err != nil {
		t.Fatal(err)
	}
	c.Parent = parent

	if err := os.RemoveAll(filepath.Join(docroot, ".wp-toolkit_c")); err != nil {
		t.Fatal(err)
	}

	p := dropperFSProbe{}.probe(c)
	if !p.Conclusive {
		t.Fatalf("probe = %+v, want a conclusive result", p)
	}
	if !p.ParentRemoved {
		t.Error("ParentRemoved = false, want true after the staging tree was removed")
	}
	if p.DocrootRemoved {
		t.Error("DocrootRemoved = true, but the document root still exists")
	}
}

func TestDropperProbeKeepsParentPresentWhenOnlyFileDeleted(t *testing.T) {
	docroot := t.TempDir()
	c := freshDropperCandidate(time.Now())
	c.Docroot = docroot
	c.Path = filepath.Join(docroot, "shell.php")
	parent, err := statDropperParent(docroot)
	if err != nil {
		t.Fatal(err)
	}
	c.Parent = parent

	p := dropperFSProbe{}.probe(c)
	if !p.Conclusive {
		t.Fatalf("probe = %+v, want a conclusive result", p)
	}
	if p.ParentRemoved {
		t.Error("ParentRemoved = true, but the directory still exists")
	}
}

func TestDropperProbeRecognizesRecreatedParent(t *testing.T) {
	docroot := t.TempDir()
	staging := filepath.Join(docroot, ".wp-toolkit_c", "wp-content", "wflogs")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	c := freshDropperCandidate(time.Now())
	c.Docroot = docroot
	c.Path = filepath.Join(staging, "config-synced.php")
	parent, err := statDropperParent(staging)
	if err != nil {
		t.Fatal(err)
	}
	c.Parent = parent

	// Keep the unlinked directory inode referenced so the recreated path
	// cannot receive the same inode number during this regression test.
	hold, err := unix.Open(staging, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(hold) })
	if err := os.RemoveAll(filepath.Join(docroot, ".wp-toolkit_c")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}

	p := dropperFSProbe{}.probe(c)
	if !p.Conclusive || !p.ParentRemoved {
		t.Fatalf("probe = %+v, want removal of the original parent identity", p)
	}
}

func TestDropperProbeDoesNotTreatDanglingParentSymlinkAsRemoved(t *testing.T) {
	docroot := t.TempDir()
	target := filepath.Join(docroot, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(docroot, "linked-parent")
	if err := os.Symlink(target, parentLink); err != nil {
		t.Fatal(err)
	}
	if _, err := statDropperParent(parentLink); err == nil {
		t.Fatal("statDropperParent followed an immediate parent symlink")
	}

	c := freshDropperCandidate(time.Now())
	c.Docroot = docroot
	c.Path = filepath.Join(parentLink, "gone.php")
	if err := os.RemoveAll(target); err != nil {
		t.Fatal(err)
	}

	p := dropperFSProbe{}.probe(c)
	if !p.Conclusive {
		t.Fatalf("probe = %+v, want conclusive path absence", p)
	}
	if p.ParentRemoved {
		t.Fatal("dangling parent symlink supplied untrusted directory-removal evidence")
	}
}

func TestDropperProbeCandidateParentRejectsAncestorSymlink(t *testing.T) {
	docroot := t.TempDir()
	target := filepath.Join(docroot, "target")
	parent := filepath.Join(target, "nested")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	ancestorLink := filepath.Join(docroot, "linked-ancestor")
	if err := os.Symlink(target, ancestorLink); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(ancestorLink, "nested", "candidate.php")
	if err := os.WriteFile(path, []byte("<?php exit;"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if _, err := statDropperCandidateParent(path, uint64(st.Dev), st.Ino); err == nil {
		t.Fatal("candidate path with a symlinked ancestor supplied parent-removal evidence")
	}
}

func TestDropperCandidateParentRejectsSuccessorAtAdmission(t *testing.T) {
	docroot := t.TempDir()
	path := filepath.Join(docroot, "candidate.php")
	if err := os.WriteFile(path, []byte("<?php exit;"), 0o600); err != nil {
		t.Fatal(err)
	}
	original, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = original.Close() })
	var st unix.Stat_t
	if err := unix.Fstat(int(original.Fd()), &st); err != nil {
		t.Fatal(err)
	}

	replacement := filepath.Join(docroot, "replacement.php")
	if err := os.WriteFile(replacement, []byte("<?php // benign successor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if _, err := statDropperCandidateParent(path, uint64(st.Dev), st.Ino); !errors.Is(err, unix.ESTALE) {
		t.Fatalf("statDropperCandidateParent() error = %v, want ESTALE", err)
	}
}
