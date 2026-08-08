package jstaint

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCorpusFilesRejectsInvalidRoots(t *testing.T) {
	t.Run("regular file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "corpus.js")
		if err := os.WriteFile(path, []byte("var x = 1;"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := corpusFiles(path); err == nil {
			t.Fatal("regular file accepted as a corpus directory")
		}
	})

	t.Run("empty directory", func(t *testing.T) {
		if _, err := corpusFiles(t.TempDir()); err == nil {
			t.Fatal("empty corpus accepted")
		}
	})
}

func TestCorpusFilesResolvesRelativeToRepositoryRoot(t *testing.T) {
	files, err := corpusFiles("internal/jstaint")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("relative repository path resolved to an empty corpus")
	}
}

func TestReadAdmissionBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		size       int
		wantPrefix bool
	}{
		{name: "small", size: 17},
		{name: "exact limit", size: MaxSourceBytes},
		{name: "oversize", size: MaxSourceBytes + 1, wantPrefix: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sample.js")
			data := make([]byte, tt.size)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			src, digest, size, err := readAdmission(path)
			if err != nil {
				t.Fatal(err)
			}
			if size != int64(tt.size) {
				t.Errorf("size = %d, want %d", size, tt.size)
			}
			wantRead := tt.size
			if wantRead > MaxSourceBytes+1 {
				wantRead = MaxSourceBytes + 1
			}
			if len(src) != wantRead {
				t.Errorf("read %d bytes, want %d", len(src), wantRead)
			}
			wantLabel := "sha256:"
			if tt.wantPrefix {
				wantLabel = "prefix_sha256:"
			}
			if want := wantLabel + sha256Hex(src); digest != want {
				t.Errorf("digest = %q, want %q", digest, want)
			}
		})
	}
}

func TestAdmissionReadLimitDoesNotOverflow(t *testing.T) {
	if got := admissionReadLimit(math.MaxInt64); got != MaxSourceBytes+1 {
		t.Errorf("read limit = %d, want %d", got, MaxSourceBytes+1)
	}
}

func TestHashManifestIncludesEveryFieldAndIgnoresOrder(t *testing.T) {
	base := []manifestRow{{
		digest:       "sha256:abc",
		size:         10,
		status:       StatusAnalyzed,
		findingCount: 0,
		adjudication: "no_finding",
	}, {
		digest:       "sha256:def",
		size:         20,
		status:       StatusParseError,
		findingCount: 0,
		adjudication: "no_finding",
	}}
	reversed := []manifestRow{base[1], base[0]}
	if got, want := hashManifest(reversed), hashManifest(base); got != want {
		t.Errorf("manifest hash depends on row order: got %s, want %s", got, want)
	}
	if reversed[0].digest != base[1].digest {
		t.Fatal("hashManifest mutated its input rows")
	}

	mutations := []manifestRow{
		{digest: "sha256:changed", size: 10, status: StatusAnalyzed, findingCount: 0, adjudication: "no_finding"},
		{digest: "sha256:abc", size: 11, status: StatusAnalyzed, findingCount: 0, adjudication: "no_finding"},
		{digest: "sha256:abc", size: 10, status: StatusParseError, findingCount: 0, adjudication: "no_finding"},
		{digest: "sha256:abc", size: 10, status: StatusAnalyzed, findingCount: 1, adjudication: "no_finding"},
		{digest: "sha256:abc", size: 10, status: StatusAnalyzed, findingCount: 0, adjudication: "false_positive"},
	}
	want := hashManifest(base)
	for i, mutation := range mutations {
		rows := []manifestRow{mutation, base[1]}
		if got := hashManifest(rows); got == want {
			t.Errorf("mutation %d did not change manifest hash", i)
		}
	}
}

func TestBlockingCorpusStatuses(t *testing.T) {
	statuses := map[Status]int{
		StatusNotCandidate:  1,
		StatusAnalyzed:      2,
		StatusOversize:      3,
		StatusParseError:    4,
		StatusResourceLimit: 5,
		StatusCanceled:      6,
		StatusPanic:         7,
	}
	want := []Status{StatusResourceLimit, StatusCanceled, StatusPanic}
	got := blockingCorpusStatuses(statuses)
	if len(got) != len(want) {
		t.Fatalf("blocking statuses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("blocking status %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestSameFileList(t *testing.T) {
	if !sameFileList([]string{"a", "b"}, []string{"a", "b"}) {
		t.Fatal("identical file lists differ")
	}
	if sameFileList([]string{"a", "b"}, []string{"b", "a"}) {
		t.Fatal("reordered file list accepted")
	}
	if sameFileList([]string{"a"}, []string{"a", "b"}) {
		t.Fatal("different-length file list accepted")
	}
}

func TestModuleVersionFallsBackToGoMod(t *testing.T) {
	if got := moduleVersion("github.com/tdewolff/parse/v2"); got == "unknown" || got == "" {
		t.Fatalf("parser module version = %q", got)
	}
}

func TestPctUsesNearestRank(t *testing.T) {
	durations := []time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond, 4 * time.Millisecond}
	for _, tt := range []struct {
		percentile int
		want       time.Duration
	}{
		{percentile: 0, want: time.Millisecond},
		{percentile: 50, want: 2 * time.Millisecond},
		{percentile: 95, want: 4 * time.Millisecond},
		{percentile: 100, want: 4 * time.Millisecond},
	} {
		if got := pct(durations, tt.percentile); got != tt.want {
			t.Errorf("p%d = %v, want %v", tt.percentile, got, tt.want)
		}
	}
}
