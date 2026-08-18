package phptaint

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCorpusGate asserts zero findings across real benign PHP. Point
// PHPTAINT_CORPUS at a tree of unpacked WordPress core and plugins:
//
//	PHPTAINT_CORPUS=/path/to/corpus go test ./internal/phptaint/ -run TestCorpusGate -v
//
// It skips when unset so the default suite does not depend on a local tree.
func TestCorpusGate(t *testing.T) {
	root := os.Getenv("PHPTAINT_CORPUS")
	if root == "" {
		t.Skip("PHPTAINT_CORPUS not set")
	}
	var scanned, gaps int
	var offenders []string
	err := filepath.Walk(root, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			// A single unreadable directory entry (permissions, a removed
			// symlink target, ...) must not abort the whole gate; skip it
			// and keep walking the rest of the corpus.
			return nil //nolint:nilerr
		}
		if !fi.Mode().IsRegular() || !strings.HasSuffix(path, ".php") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			// Same reasoning: a file that vanished or became unreadable
			// between the stat above and this read is skipped, not fatal.
			return nil //nolint:nilerr
		}
		rep := Analyze(context.Background(), src)
		switch rep.Status {
		case StatusAnalyzed:
			scanned++
			if len(rep.Results) > 0 {
				offenders = append(offenders, path)
			}
		case StatusNotCandidate:
			scanned++
		default:
			gaps++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	t.Logf("analyzed %d file(s), %d coverage gap(s)", scanned, gaps)
	if len(offenders) > 0 {
		limit := len(offenders)
		if limit > 20 {
			limit = 20
		}
		t.Errorf("%d false positive(s) on benign corpus, first %d: %v",
			len(offenders), limit, offenders[:limit])
	}
}
