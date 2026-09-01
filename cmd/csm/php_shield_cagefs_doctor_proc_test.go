package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// writeFakeProc builds a /proc tree: pid 1 in the root namespace, plus one
// process per cage. A cage whose value is true has the event mount in its
// mount table.
func writeFakeProc(t *testing.T, cages []bool) string {
	t.Helper()

	root := t.TempDir()
	mkProc := func(pid, ns, mounts string) {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(ns, filepath.Join(dir, "ns", "mnt")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "mounts"), []byte(mounts), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	const rootNS = "mnt:[4026531840]"
	// init plus a daemon that shares its namespace: neither is a cage.
	mkProc("1", rootNS, "/dev/md127 / xfs rw 0 0\n")
	mkProc("2", rootNS, "/dev/md127 / xfs rw 0 0\n")

	for i, mounted := range cages {
		body := "/dev/md127 / xfs rw 0 0\n"
		if mounted {
			body += "/dev/md127 " + phpShieldEventDir + " xfs rw 0 0\n"
		}
		mkProc(strconv.Itoa(1000+i), "mnt:[40265334"+strconv.Itoa(90+i)+"]", body)
	}
	return root
}

func withFakeProc(t *testing.T, cages []bool) {
	t.Helper()
	oldProc, oldUID := procPath, cagefsMinUID
	procPath = writeFakeProc(t, cages)
	// The fixture's /proc entries are owned by whoever runs the test, which is
	// root in CI and an ordinary user locally. Sample every uid so the test
	// exercises the namespace logic rather than the host's uid numbering.
	cagefsMinUID = 0
	t.Cleanup(func() { procPath, cagefsMinUID = oldProc, oldUID })
}

// The bug this replaced: keying on the cage skeleton reported "applied" for the
// whole server once a single user had been remounted, while every other cage
// was still blind. A per-cage mount table cannot be fooled that way.
func TestSampleCageShieldMountsCountsPerCageNotServerWide(t *testing.T) {
	withFakeProc(t, []bool{true, false, false})

	missing, sampled, err := sampleCageShieldMounts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sampled == 0 {
		t.Fatal("sampled 0 cages, want the cage processes counted")
	}
	if missing == 0 {
		t.Errorf("missing = 0 with 2 unmounted cages out of %d sampled", sampled)
	}
}

// Every cage mounted: nothing to report.
func TestSampleCageShieldMountsCleanWhenAllMounted(t *testing.T) {
	withFakeProc(t, []bool{true, true})

	missing, sampled, err := sampleCageShieldMounts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if missing != 0 {
		t.Errorf("missing = %d of %d, want 0", missing, sampled)
	}
}

// Processes sharing init's mount namespace are not cages. Counting them would
// make a plain Debian host report itself full of blind cages.
func TestSampleCageShieldMountsIgnoresRootNamespace(t *testing.T) {
	withFakeProc(t, nil)

	_, sampled, err := sampleCageShieldMounts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sampled != 0 {
		t.Errorf("sampled = %d, want 0 when only root-namespace processes exist", sampled)
	}
}

// The mount point is a whole field, so a longer path that merely starts with
// the event directory is not this mount.
func TestMountsContainMatchesWholeMountPoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mounts")
	body := "/dev/md127 " + phpShieldEventDir + "-old xfs rw 0 0\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := mountsContain(path, phpShieldEventDir)
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Errorf("%q must not match the longer mount point in %q", phpShieldEventDir, body)
	}
}
