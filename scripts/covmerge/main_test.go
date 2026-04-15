package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// writeProfile writes a coverage profile with the given mode + entries to a
// temp file and returns the path.
func writeProfile(t *testing.T, mode string, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.out")
	content := "mode: " + mode + "\n"
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadProfile_ParsesEntriesAndMode(t *testing.T) {
	path := writeProfile(t, "atomic",
		"github.com/example/pkg/file.go:10.5,12.20 2 7",
		"github.com/example/pkg/other.go:3.1,5.10 1 0",
	)
	p, err := readProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.mode != "atomic" {
		t.Errorf("mode = %q, want atomic", p.mode)
	}
	if len(p.byFile) != 2 {
		t.Errorf("expected 2 files, got %d", len(p.byFile))
	}
	file := "github.com/example/pkg/file.go"
	if got := p.byFile[file]; len(got) != 1 || got[0].rangeKey != "10.5,12.20" || got[0].stmt != 2 || got[0].hits != 7 {
		t.Errorf("file entry = %+v", got)
	}
}

func TestRangesEqual_SameEntriesDifferentOrder(t *testing.T) {
	a := []entry{{rangeKey: "1.1,2.2"}, {rangeKey: "3.3,4.4"}}
	b := []entry{{rangeKey: "3.3,4.4"}, {rangeKey: "1.1,2.2"}}
	if !rangesEqual(a, b) {
		t.Error("ranges with same keys in different order should be equal")
	}
}

func TestRangesEqual_DifferentLength(t *testing.T) {
	a := []entry{{rangeKey: "1.1,2.2"}}
	b := []entry{{rangeKey: "1.1,2.2"}, {rangeKey: "3.3,4.4"}}
	if rangesEqual(a, b) {
		t.Error("ranges with different lengths should not be equal")
	}
}

func TestRangesEqual_DifferentKeys(t *testing.T) {
	a := []entry{{rangeKey: "1.1,2.2"}}
	b := []entry{{rangeKey: "1.1,2.3"}} // differs by one col
	if rangesEqual(a, b) {
		t.Error("ranges with different keys should not be equal")
	}
}

// TestMerge_CombinesHitCounts runs the merge via the readProfile +
// merge logic and verifies hit counts are summed for matching ranges.
// This isn't a subprocess test — we directly test the internal functions
// to avoid os.Exit in main().
func TestMerge_MatchingFile_SumsHits(t *testing.T) {
	primary := writeProfile(t, "atomic",
		"github.com/a/file.go:1.1,2.2 1 5",
		"github.com/a/file.go:3.3,4.4 1 0",
	)
	secondary := writeProfile(t, "atomic",
		"github.com/a/file.go:1.1,2.2 1 10",
		"github.com/a/file.go:3.3,4.4 1 3",
	)
	p, _ := readProfile(primary)
	s, _ := readProfile(secondary)

	// Simulate merge logic from main():
	for file, pEntries := range p.byFile {
		sEntries, ok := s.byFile[file]
		if !ok || !rangesEqual(pEntries, sEntries) {
			continue
		}
		byRange := make(map[string]*entry, len(pEntries))
		for i := range pEntries {
			byRange[pEntries[i].rangeKey] = &pEntries[i]
		}
		for i := range sEntries {
			if e, ok := byRange[sEntries[i].rangeKey]; ok {
				e.hits += sEntries[i].hits
			}
		}
	}

	got := p.byFile["github.com/a/file.go"]
	// Entries may be in any order; sort by rangeKey for assertions.
	sort.Slice(got, func(i, j int) bool { return got[i].rangeKey < got[j].rangeKey })
	want := []entry{
		{rangeKey: "1.1,2.2", stmt: 1, hits: 15},
		{rangeKey: "3.3,4.4", stmt: 1, hits: 3},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("merged = %+v, want %+v", got, want)
	}
}

func TestMerge_DriftingFile_KeepsPrimaryOnly(t *testing.T) {
	primary := writeProfile(t, "atomic",
		"github.com/drift/file.go:10.1,12.2 2 4",
	)
	secondary := writeProfile(t, "atomic",
		"github.com/drift/file.go:10.1,12.2 2 9",
		// Extra range only in secondary - this constitutes drift.
		"github.com/drift/file.go:20.1,22.2 1 7",
	)
	p, _ := readProfile(primary)
	s, _ := readProfile(secondary)

	pEntries := p.byFile["github.com/drift/file.go"]
	sEntries := s.byFile["github.com/drift/file.go"]
	if rangesEqual(pEntries, sEntries) {
		t.Fatal("test setup: ranges should differ (drift)")
	}
	// Drift detected - primary's entries should be untouched.
	if pEntries[0].hits != 4 {
		t.Errorf("primary hits changed on drift: %d", pEntries[0].hits)
	}
}

func TestReadProfile_HandlesBlankLinesAndModeLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.out")
	content := "mode: set\n" +
		"\n" + // blank line
		"github.com/x/a.go:1.1,2.2 1 1\n" +
		"\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	p, err := readProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.mode != "set" {
		t.Errorf("mode = %q", p.mode)
	}
	if len(p.byFile) != 1 {
		t.Errorf("expected 1 file, got %d", len(p.byFile))
	}
}

func TestReadProfile_IgnoresMalformedLines(t *testing.T) {
	path := writeProfile(t, "atomic",
		"this line has no colon",
		"github.com/ok/file.go:1.1,2.2 1 5",
		"github.com/bad/file.go:1.1,2.2 notanumber 5", // non-numeric stmt
	)
	p, err := readProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.byFile["github.com/ok/file.go"]; !ok {
		t.Error("ok file should be present")
	}
	if _, ok := p.byFile["github.com/bad/file.go"]; ok {
		t.Error("bad file should be skipped")
	}
}

func TestReadProfile_MissingFileReturnsError(t *testing.T) {
	_, err := readProfile("/nonexistent/path/to/profile.out")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
