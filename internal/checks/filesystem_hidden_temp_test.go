package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// tempGlobOS serves the hardcoded temp-dir globs from a real directory so the
// files under test have real modes and real inodes.
type tempGlobOS struct {
	realOS
	roots map[string]string // glob pattern -> real directory
}

func (t tempGlobOS) Glob(pattern string) ([]string, error) {
	dir, ok := t.roots[pattern]
	if !ok {
		return nil, nil
	}
	return filepath.Glob(filepath.Join(dir, ".*"))
}

func hiddenFileFindings(t *testing.T, o OS) []alert.Finding {
	t.Helper()
	withMockOS(t, o)
	var out []alert.Finding
	for _, f := range CheckFilesystem(context.Background(), &config.Config{}, nil) {
		if f.Check == "suspicious_file" && strings.Contains(f.Message, "hidden file") {
			out = append(out, f)
		}
	}
	return out
}

// Every hidden file in a temp directory was reported at HIGH with no signal
// beyond the leading dot, so root-owned infrastructure output (cPanel AutoSSL
// working files, Qt runtime state) came back as a security finding. A hidden
// file is only interesting when it could execute.
func TestHiddenTempFileNeedsAnExecutableSignal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".autossl-example.out"), []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".qt"), []byte("[General]\nx=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := hiddenFileFindings(t, tempGlobOS{roots: map[string]string{"/tmp/.*": dir}})
	if len(got) != 0 {
		t.Fatalf("inert hidden data files reported as suspicious: %+v", got)
	}
}

// A hidden file that can execute is still reported: an executable bit, ELF
// magic, or a script marker each stand on their own.
func TestHiddenTempFileReportsExecutableCandidates(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".payload"), []byte("harmless\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".elf"), append([]byte("\x7fELF"), make([]byte, 64)...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".shell"), []byte("#!/bin/sh\nid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".web"), []byte("<?php system($_GET['c']); ?>\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := hiddenFileFindings(t, tempGlobOS{roots: map[string]string{"/tmp/.*": dir}})
	if len(got) != 4 {
		t.Fatalf("executable-capable hidden files = %d, want 4: %+v", len(got), got)
	}
}

// On CloudLinux /var/tmp is the same filesystem as /tmp, so the same physical
// file is reachable through two of the scanned roots and was reported twice.
func TestHiddenTempFileReportedOncePerInode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".payload"), []byte("x\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := hiddenFileFindings(t, tempGlobOS{roots: map[string]string{
		"/tmp/.*":     dir,
		"/var/tmp/.*": dir,
	}})
	if len(got) != 1 {
		t.Fatalf("the same file behind two temp roots produced %d findings, want 1: %+v", len(got), got)
	}
}
