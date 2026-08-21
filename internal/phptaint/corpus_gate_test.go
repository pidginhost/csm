package phptaint

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// minCorpusFiles is the floor TestCorpusGate requires PHPTAINT_CORPUS to
// have actually scanned. Without it, a typo'd or empty path walks zero
// files, finds zero offenders, and passes -- reporting success for a gate
// that never ran, which is worse than no gate at all. 100 is comfortably
// below every real corpus this gate has been run against (the smallest
// single plugin in the reference corpus has 2 files; the reference corpus
// as a whole has 8,630), so it will not go brittle as the corpus's plugin
// mix changes over time, while still being far too high for an empty or
// wrong directory (which scans 0) to pass by accident.
const minCorpusFiles = 100

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
	var offenders, panics []string
	err := filepath.Walk(root, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			// A single unreadable directory entry (permissions, a removed
			// symlink target, ...) must not abort the whole gate; skip it
			// and keep walking the rest of the corpus.
			return nil //nolint:nilerr
		}
		// Deliberately NOT restricted to .php. The deep scan applies no
		// extension filter (internal/checks/yara_deep.go walks every readable
		// file under the size cap), so a .php-only corpus tests an input space
		// the analyzer never actually sees. Translation catalogues, compiled
		// binaries and minified bundles all reach it in production.
		if !fi.Mode().IsRegular() || fi.Size() > int64(MaxSourceBytes) {
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
		case StatusPanic:
			scanned++
			panics = append(panics, path)
		default:
			gaps++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	t.Logf("analyzed %d file(s), %d coverage gap(s)", scanned, gaps)
	if scanned < minCorpusFiles {
		t.Fatalf("only %d file(s) scanned under PHPTAINT_CORPUS=%s, want at least %d: "+
			"the gate cannot prove anything against a near-empty or wrong directory", scanned, root, minCorpusFiles)
	}
	if len(panics) > 0 {
		limit := len(panics)
		if limit > 10 {
			limit = 10
		}
		t.Errorf("analyzer panicked on %d corpus file(s); first %d: %v", len(panics), limit, panics[:limit])
	}
	if len(offenders) > 0 {
		limit := len(offenders)
		if limit > 20 {
			limit = 20
		}
		t.Errorf("%d false positive(s) on benign corpus, first %d: %v",
			len(offenders), limit, offenders[:limit])
	}
}
