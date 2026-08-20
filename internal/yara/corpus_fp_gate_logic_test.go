//go:build yara

package yara_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	csmyara "github.com/pidginhost/csm/internal/yara"
)

func TestCorpusMaxFileBytesMatchesScheduledDeepScan(t *testing.T) {
	if got := checks.FullScanMaxFileBytes(nil); got != corpusMaxFileBytes {
		t.Fatalf("corpus limit = %d, scheduled deep-scan default = %d", corpusMaxFileBytes, got)
	}
}

func TestScanCleanCorpusRejectsBelowFloor(t *testing.T) {
	root := t.TempDir()
	writeCorpusFile(t, root, "only.php", "<?php echo 'clean';")

	_, err := scanCleanCorpus(root, 2, corpusMaxFileBytes, cleanCorpusScan)
	if err == nil || !strings.Contains(err.Error(), "below the 2-file floor") {
		t.Fatalf("scanCleanCorpus error = %v, want corpus floor failure", err)
	}
}

func TestScanCleanCorpusDoesNotCountSkippedArchives(t *testing.T) {
	root := t.TempDir()
	writeCorpusFile(t, root, "one.zip", "PK\x03\x04stored content")
	writeCorpusFile(t, root, "two.zip", "PK\x03\x04more stored content")

	scanCalls := 0
	_, err := scanCleanCorpus(root, 2, corpusMaxFileBytes, func([]byte) ([]csmyara.Match, error) {
		scanCalls++
		return nil, nil
	})
	if err == nil || !strings.Contains(err.Error(), "below the 2-file floor") {
		t.Fatalf("scanCleanCorpus error = %v, want corpus floor failure", err)
	}
	if scanCalls != 0 {
		t.Fatalf("archive content reached the rule scanner %d time(s), want 0", scanCalls)
	}
}

func TestScanCleanCorpusSurfacesScannerError(t *testing.T) {
	root := t.TempDir()
	path := writeCorpusFile(t, root, "clean.php", "<?php echo 'clean';")

	_, err := scanCleanCorpus(root, 1, corpusMaxFileBytes, func([]byte) ([]csmyara.Match, error) {
		return nil, errors.New("engine stopped")
	})
	if err == nil || !strings.Contains(err.Error(), "scanning "+path) || !strings.Contains(err.Error(), "engine stopped") {
		t.Fatalf("scanCleanCorpus error = %v, want scanner failure with path", err)
	}
}

func TestReadCorpusFileBoundsContentToScanLimit(t *testing.T) {
	root := t.TempDir()
	path := writeCorpusFile(t, root, "growing.php", "content beyond limit")

	_, err := readCorpusFile(path, 4)
	if err == nil || !strings.Contains(err.Error(), "exceeds the 4-byte scan limit") {
		t.Fatalf("readCorpusFile error = %v, want bounded-read failure", err)
	}
}

func TestScanCleanCorpusRecordsHitsAndExamples(t *testing.T) {
	root := t.TempDir()
	first := writeCorpusFile(t, root, "a.php", "first")
	writeCorpusFile(t, root, "b.php", "second")

	result, err := scanCleanCorpus(root, 2, corpusMaxFileBytes, func([]byte) ([]csmyara.Match, error) {
		return []csmyara.Match{{RuleName: "test_rule"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.scanned != 2 || result.hits["test_rule"] != 2 || result.examples["test_rule"] != first {
		t.Fatalf("scan result = %+v, want 2 hits with first example %s", result, first)
	}
}

func TestScanCleanCorpusSurfacesReadErrorAfterFloor(t *testing.T) {
	root := t.TempDir()
	writeCorpusFile(t, root, "a.php", "<?php echo 'a';")
	writeCorpusFile(t, root, "b.php", "<?php echo 'b';")
	badPath := writeCorpusFile(t, root, "z.php", "<?php echo 'z';")

	readFile := func(path string, _ int64) ([]byte, error) {
		if path == badPath {
			return nil, fs.ErrPermission
		}
		return os.ReadFile(path) // #nosec G304 -- paths come from t.TempDir
	}
	_, err := scanCleanCorpusWith(root, 2, corpusMaxFileBytes, cleanCorpusScan, filepath.Walk, readFile)
	if err == nil || !strings.Contains(err.Error(), "reading "+badPath) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("scanCleanCorpusWith error = %v, want unreadable-file failure after clearing floor", err)
	}
}

func TestScanCleanCorpusSurfacesWalkErrorAfterFloor(t *testing.T) {
	root := t.TempDir()
	writeCorpusFile(t, root, "a.php", "<?php echo 'a';")
	writeCorpusFile(t, root, "b.php", "<?php echo 'b';")
	badPath := filepath.Join(root, "unreadable")

	walk := func(root string, visit filepath.WalkFunc) error {
		if err := filepath.Walk(root, visit); err != nil {
			return err
		}
		return visit(badPath, nil, fs.ErrPermission)
	}
	readFile := func(path string, _ int64) ([]byte, error) {
		return os.ReadFile(path) // #nosec G304 -- paths come from t.TempDir
	}
	_, err := scanCleanCorpusWith(root, 2, corpusMaxFileBytes, cleanCorpusScan, walk, readFile)
	if err == nil || !strings.Contains(err.Error(), "walking "+badPath) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("scanCleanCorpusWith error = %v, want walk failure after clearing floor", err)
	}
}

func cleanCorpusScan([]byte) ([]csmyara.Match, error) {
	return nil, nil
}

func writeCorpusFile(t *testing.T, root, name, content string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
