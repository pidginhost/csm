package checks

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A stock PHP handler renders ".phps" as highlighted source instead of running
// it, so the extension was left out of the content-analysis index entirely. An
// attacker who stages a dropper as ".phps" therefore gets a payload that no
// content scanner ever reads, one rename away from live execution. Indexing is
// what feeds content analysis, so the extension has to reach the index; whether
// the file is malicious stays a content decision.

func TestScanDirForPHPContextIndexesPhpsStagedPayload(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, "index.phps")
	if err := os.WriteFile(staged, []byte("<?php $x = 1;"), 0o644); err != nil {
		t.Fatal(err)
	}

	cache := make(dirMtimeCache)
	var entries []string
	scanDirForPHPContext(context.Background(), dir, 2, cache, nil, false, phpHandlerOverlay{}, &entries)

	if !slices.Contains(entries, staged) {
		t.Errorf("index = %v, want it to contain the staged .phps payload %s", entries, staged)
	}
}

// The tmp-dir index feeds the same content analysis, and /tmp is where droppers
// land before they are moved into a web root.
func TestScanDirForSuspiciousExtIndexesPhps(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, "payload.phps")
	if err := os.WriteFile(staged, []byte("<?php $x = 1;"), 0o644); err != nil {
		t.Fatal(err)
	}

	cache := make(dirMtimeCache)
	var entries []string
	scanDirForSuspiciousExt(dir, 2, cache, nil, false, &entries)

	if !slices.Contains(entries, staged) {
		t.Errorf("index = %v, want it to contain the staged .phps payload %s", entries, staged)
	}
}

// Indexing ".phps" must not reclassify it as executable: the realtime dropper
// tracker and the PHP-handler gate both key off that predicate, and a stock
// handler genuinely does not run ".phps".
func TestPhpsIsNotExecutable(t *testing.T) {
	if isExecutablePHPName("index.phps") {
		t.Error("isExecutablePHPName(index.phps) = true, want false: stock handlers render .phps as source")
	}
}
