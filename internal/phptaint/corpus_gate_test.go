package phptaint

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// minCorpusPHPSources is the floor TestCorpusGate requires PHPTAINT_CORPUS to
// contain. Production also feeds non-PHP files to the analyzer, but counting
// those toward the floor would let a directory of 100 text or media files pass
// a gate intended to exercise benign PHP. An open tag is the same content-based
// boundary production uses to recognize possible PHP; names and extensions do
// not affect which files the gate analyzes.
const minCorpusPHPSources = 100

type corpusGateStats struct {
	inputs, phpSources, gaps int
	offenders, panics        []string
}

func (s *corpusGateStats) observe(path string, mayBePHP bool, report Report) {
	s.inputs++
	if mayBePHP {
		s.phpSources++
	}
	switch report.Status {
	case StatusAnalyzed:
		if len(report.Results) > 0 {
			s.offenders = append(s.offenders, path)
		}
	case StatusNotCandidate:
	case StatusPanic:
		s.gaps++
		s.panics = append(s.panics, path)
	default:
		s.gaps++
	}
}

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
	var stats corpusGateStats
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
		stats.observe(path, MayBePHPSource(src), rep)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	t.Logf("read %d file(s), found %d PHP-looking source(s) and %d coverage gap(s)", stats.inputs, stats.phpSources, stats.gaps)
	if stats.phpSources < minCorpusPHPSources {
		t.Fatalf("only %d PHP-looking source(s) under PHPTAINT_CORPUS=%s, want at least %d: "+
			"the gate cannot prove anything against a near-empty, wrong, or non-PHP directory", stats.phpSources, root, minCorpusPHPSources)
	}
	if len(stats.panics) > 0 {
		limit := len(stats.panics)
		if limit > 10 {
			limit = 10
		}
		t.Errorf("analyzer panicked on %d corpus file(s); first %d: %v", len(stats.panics), limit, stats.panics[:limit])
	}
	if len(stats.offenders) > 0 {
		limit := len(stats.offenders)
		if limit > 20 {
			limit = 20
		}
		t.Errorf("%d false positive(s) on benign corpus, first %d: %v",
			len(stats.offenders), limit, stats.offenders[:limit])
	}
}

func TestCorpusGateFloorExcludesNonPHPSources(t *testing.T) {
	var stats corpusGateStats
	for i := 0; i < minCorpusPHPSources; i++ {
		stats.observe("plain.txt", false, Report{Status: StatusNotCandidate})
	}
	if stats.inputs != minCorpusPHPSources || stats.phpSources != 0 {
		t.Fatalf("non-PHP inputs counted toward corpus floor: %+v", stats)
	}

	// A source without flow keywords is still PHP and must count even when the
	// pre-filter can finish it as not-candidate. A non-.php file with an open tag
	// follows the same rule because production does not classify by extension.
	stats.observe("clean.php", true, Report{Status: StatusNotCandidate})
	stats.observe("panic.mo", true, Report{Status: StatusPanic})
	if stats.phpSources != 2 || stats.gaps != 1 || len(stats.panics) != 1 {
		t.Fatalf("PHP source accounting is inconsistent: %+v", stats)
	}
}
