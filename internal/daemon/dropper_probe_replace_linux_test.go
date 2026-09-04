//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDropperProbeMarksRegularSuccessorAtPath(t *testing.T) {
	docroot := t.TempDir()
	path := filepath.Join(docroot, "config-synced.php")
	if err := os.WriteFile(path, []byte("<?php exit('Access denied'); __halt_compiler(); ?>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := freshDropperCandidate(time.Now())
	c.Docroot = docroot
	c.Path = path
	c.Inode = 1 // deliberately not the on-disk inode: the path was taken over

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

	p := dropperFSProbe{}.probe(c)
	if !p.Conclusive {
		t.Fatalf("probe = %+v, want a conclusive result", p)
	}
	if p.ParentRemoved {
		t.Error("ParentRemoved = true, but the directory still exists")
	}
}
