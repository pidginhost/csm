package jstaint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"testing"
	"time"
)

// corpusEnv names the environment variable that points the opt-in corpus gate at
// a tree of real JavaScript files. The gate never runs in normal CI: it is a
// false-positive measurement over private host content, so it is skipped unless
// an operator sets this variable to a corpus directory.
const corpusEnv = "CSM_JSTAINT_CORPUS"

// Budgets from the design's acceptance criteria.
const (
	corpusTotalBudget   = 90 * time.Second
	corpusPerFileBudget = 500 * time.Millisecond
)

// TestCorpusGate runs the production admission and analysis over every regular
// file under the corpus directory and requires zero findings, since the corpus
// is a hand-adjudicated false-positive set. It also enforces the wall-clock
// budgets and records the environment and distribution metrics the design asks
// for. A finding here is a false positive that blocks release.
func TestCorpusGate(t *testing.T) {
	root := os.Getenv(corpusEnv)
	if root == "" {
		t.Skipf("set %s to a corpus directory to run the opt-in false-positive gate", corpusEnv)
	}

	var (
		files      []string
		statuses   = map[Status]int{}
		durations  []time.Duration
		findings   []finding
		totalStart = time.Now()
		digester   = sha256.New()
	)
	type manifestRow struct {
		digest string
		size   int64
	}
	var manifest []manifestRow

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk corpus: %v", err)
	}
	sort.Strings(files)

	var startMem, endMem runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&startMem)

	for _, path := range files {
		src, oversizeDigest, size, err := readAdmission(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		start := time.Now()
		rep := Analyze(context.Background(), src)
		elapsed := time.Since(start)

		durations = append(durations, elapsed)
		statuses[rep.Status]++
		if elapsed > corpusPerFileBudget {
			t.Errorf("per-file budget exceeded: %s took %v", filepath.Base(path), elapsed)
		}
		if rep.Status == StatusAnalyzed && len(rep.Results) > 0 {
			findings = append(findings, finding{path: path, report: rep})
		}
		row := manifestRow{size: size}
		if oversizeDigest != "" {
			row.digest = "prefix_sha256:" + oversizeDigest
		} else {
			row.digest = "sha256:" + sha256Hex(src)
		}
		manifest = append(manifest, row)
	}

	runtime.ReadMemStats(&endMem)
	total := time.Since(totalStart)

	sort.Slice(manifest, func(i, j int) bool {
		if manifest[i].digest != manifest[j].digest {
			return manifest[i].digest < manifest[j].digest
		}
		return manifest[i].size < manifest[j].size
	})
	for _, row := range manifest {
		// A hash.Hash write never returns an error.
		_, _ = io.WriteString(digester, row.digest)
		_, _ = io.WriteString(digester, "\x00")
	}

	logCorpusReport(t, len(files), total, durations, statuses,
		endMem.TotalAlloc-startMem.TotalAlloc, peakRSSBytes(),
		hex.EncodeToString(digester.Sum(nil)))

	if len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("false positive: %s -> %d flow(s), first %+v",
				f.path, len(f.report.Results), f.report.Results[0])
		}
		t.Fatalf("%d corpus file(s) produced a finding; the gate requires zero", len(findings))
	}
	if total > corpusTotalBudget {
		t.Errorf("total budget exceeded: %v > %v", total, corpusTotalBudget)
	}
}

type finding struct {
	path   string
	report Report
}

// readAdmission reads a file the way production does: at most MaxSourceBytes plus
// one byte, so an exact-limit file is distinguished from a truncated prefix. For
// an oversize file it returns a prefix digest instead of reading the whole file.
func readAdmission(path string) (src []byte, oversizePrefixDigest string, size int64, err error) {
	f, err := os.Open(path) // #nosec G304 -- corpus path from an operator-set env var, test-only
	if err != nil {
		return nil, "", 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, "", 0, err
	}
	size = info.Size()
	// Read at most MaxSourceBytes plus one byte so an exact-limit file is told
	// apart from a truncated prefix, but size the buffer to the file so a small
	// file does not allocate the whole ceiling.
	limit := int64(MaxSourceBytes) + 1
	if size+1 < limit {
		limit = size + 1
	}
	buf := make([]byte, limit)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, "", 0, err
	}
	buf = buf[:n]
	if n > MaxSourceBytes {
		return buf, sha256Hex(buf), size, nil
	}
	return buf, "", size, nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func peakRSSBytes() int64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	// Maxrss is bytes on darwin and kilobytes on linux.
	if runtime.GOOS == "linux" {
		return ru.Maxrss * 1024
	}
	return ru.Maxrss
}

func logCorpusReport(t *testing.T, count int, total time.Duration, durations []time.Duration,
	statuses map[Status]int, allocBytes uint64, peakRSS int64, manifestSHA string) {
	t.Helper()
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	t.Logf("corpus files:        %d", count)
	t.Logf("total wall clock:    %v (budget %v)", total, corpusTotalBudget)
	t.Logf("per-file p50/p95/max: %v / %v / %v", pct(durations, 50), pct(durations, 95), pct(durations, 100))
	t.Logf("allocated bytes:     %d", allocBytes)
	t.Logf("peak RSS bytes:      %d", peakRSS)
	for s := StatusNotCandidate; s <= StatusPanic; s++ {
		t.Logf("status %-14s %d", s.String()+":", statuses[s])
	}
	t.Logf("manifest sha256:     %s", manifestSHA)
	t.Logf("go version:          %s", runtime.Version())
	t.Logf("GOARCH/NumCPU:       %s / %d", runtime.GOARCH, runtime.NumCPU())
}

func pct(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	idx := (p * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
