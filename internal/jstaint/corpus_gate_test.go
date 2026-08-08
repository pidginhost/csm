package jstaint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

// corpusEnv names the environment variable that points the opt-in corpus gate at
// a tree of real JavaScript files. The gate never runs in normal CI: it is a
// false-positive measurement over private host content, so it is skipped unless
// an operator sets this variable to a corpus directory.
const corpusEnv = "CSM_JSTAINT_CORPUS"

const (
	corpusMeasuredPasses = 3
	corpusTotalBudget    = 90 * time.Second
	corpusPerFileBudget  = 500 * time.Millisecond
)

type corpusPass struct {
	fileCount     int
	byteCount     uint64
	endToEnd      time.Duration
	analysisTotal time.Duration
	durations     []time.Duration
	statuses      map[Status]int
	findings      []finding
	allocBytes    uint64
	peakRSS       int64
	manifestSHA   string
}

type manifestRow struct {
	digest       string
	size         int64
	status       Status
	findingCount int
	adjudication string
}

type finding struct {
	digest string
	flows  int
}

// TestCorpusGate runs production admission and analysis over every regular file
// under the corpus directory. The corpus is a hand-adjudicated false-positive
// set, so any finding blocks release. Timing and memory measurements are
// reported for review rather than enforced as hardware-sensitive test limits.
func TestCorpusGate(t *testing.T) {
	root := os.Getenv(corpusEnv)
	if root == "" {
		t.Skipf("set %s to a corpus directory to run the opt-in false-positive gate", corpusEnv)
	}

	files, err := corpusFiles(root)
	if err != nil {
		t.Fatalf("enumerate corpus: %v", err)
	}

	// Warm parser and allocator paths before taking the three release
	// measurements. Functional failures still matter during the warm-up.
	warmup, err := runCorpusPass(files)
	if err != nil {
		t.Fatalf("warm-up corpus pass: %v", err)
	}
	validateCorpusPass(t, "warm-up", warmup)

	passes := make([]corpusPass, 0, corpusMeasuredPasses)
	for i := 0; i < corpusMeasuredPasses; i++ {
		measuredFiles, err := corpusFiles(root)
		if err != nil {
			t.Fatalf("enumerate corpus before measured pass %d: %v", i+1, err)
		}
		if !sameFileList(measuredFiles, files) {
			t.Fatalf("corpus file set changed before measured pass %d", i+1)
		}
		pass, err := runCorpusPass(measuredFiles)
		if err != nil {
			t.Fatalf("measured corpus pass %d: %v", i+1, err)
		}
		validateCorpusPass(t, fmt.Sprintf("measured pass %d", i+1), pass)
		logCorpusPass(t, i+1, pass)
		passes = append(passes, pass)
	}

	for i := 1; i < len(passes); i++ {
		if passes[i].manifestSHA != passes[0].manifestSHA {
			t.Fatalf("corpus changed between measured passes: manifest %d differs from pass 1", i+1)
		}
	}
	logCorpusSummary(t, passes)
}

func corpusFiles(root string) ([]string, error) {
	if !filepath.IsAbs(root) {
		repoRoot, err := repositoryRoot()
		if err != nil {
			return nil, err
		}
		root = filepath.Join(repoRoot, root)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve corpus root: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("stat corpus root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("corpus root is not a directory")
	}

	var files []string
	err = filepath.WalkDir(resolved, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("corpus contains no regular files")
	}
	sort.Strings(files)
	return files, nil
}

func sameFileList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func runCorpusPass(files []string) (corpusPass, error) {
	pass := corpusPass{
		fileCount: len(files),
		statuses:  make(map[Status]int),
	}
	rows := make([]manifestRow, 0, len(files))

	runtime.GC()
	var startMem, endMem runtime.MemStats
	runtime.ReadMemStats(&startMem)
	totalStart := time.Now()

	for i, path := range files {
		src, digest, size, err := readAdmission(path)
		if err != nil {
			return corpusPass{}, fmt.Errorf("read corpus entry %d: %w", i+1, err)
		}
		if math.MaxUint64-pass.byteCount < uint64(size) {
			return corpusPass{}, fmt.Errorf("corpus byte count overflow")
		}
		pass.byteCount += uint64(size)

		start := time.Now()
		rep := Analyze(context.Background(), src)
		elapsed := time.Since(start)
		pass.analysisTotal += elapsed
		pass.durations = append(pass.durations, elapsed)
		pass.statuses[rep.Status]++

		flowCount := rep.TotalResults
		if len(rep.Results) > flowCount {
			flowCount = len(rep.Results)
		}
		findingCount := 0
		adjudication := "no_finding"
		if flowCount > 0 {
			findingCount = 1
			adjudication = "false_positive"
			pass.findings = append(pass.findings, finding{digest: digest, flows: flowCount})
		}
		rows = append(rows, manifestRow{
			digest:       digest,
			size:         size,
			status:       rep.Status,
			findingCount: findingCount,
			adjudication: adjudication,
		})
	}

	pass.endToEnd = time.Since(totalStart)
	runtime.ReadMemStats(&endMem)
	pass.allocBytes = endMem.TotalAlloc - startMem.TotalAlloc
	peakRSS, err := peakRSSBytes()
	if err != nil {
		return corpusPass{}, err
	}
	pass.peakRSS = peakRSS
	pass.manifestSHA = hashManifest(rows)
	return pass, nil
}

func validateCorpusPass(t *testing.T, label string, pass corpusPass) {
	t.Helper()
	if len(pass.findings) != 0 {
		for _, f := range pass.findings {
			t.Errorf("%s false positive: %s produced %d flow(s)", label, f.digest, f.flows)
		}
		t.Fatalf("%s produced findings in %d corpus file(s); the gate requires zero", label, len(pass.findings))
	}
	for _, status := range blockingCorpusStatuses(pass.statuses) {
		if count := pass.statuses[status]; count != 0 {
			t.Errorf("%s returned %s for %d corpus file(s)", label, status, count)
		}
	}
}

func blockingCorpusStatuses(statuses map[Status]int) []Status {
	var blocked []Status
	for _, status := range []Status{StatusResourceLimit, StatusCanceled, StatusPanic} {
		if statuses[status] != 0 {
			blocked = append(blocked, status)
		}
	}
	return blocked
}

// readAdmission reads a file the way production admission does: at most
// MaxSourceBytes plus one byte, so an exact-limit file is distinguished from a
// truncated prefix. An oversize digest never requires reading the full file.
func readAdmission(path string) (src []byte, digest string, size int64, err error) {
	f, err := os.Open(path) // #nosec G304 -- corpus path from an operator-set env var, test-only
	if err != nil {
		return nil, "", 0, err
	}
	defer f.Close()

	before, err := f.Stat()
	if err != nil {
		return nil, "", 0, err
	}
	size = before.Size()
	buf := make([]byte, admissionReadLimit(size))
	n, readErr := io.ReadFull(f, buf)
	if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
		return nil, "", 0, readErr
	}

	after, err := f.Stat()
	if err != nil {
		return nil, "", 0, err
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, "", 0, fmt.Errorf("corpus file changed while being read")
	}
	if (size <= MaxSourceBytes && int64(n) != size) || (size > MaxSourceBytes && n <= MaxSourceBytes) {
		return nil, "", 0, fmt.Errorf("corpus file changed while being read")
	}

	buf = buf[:n]
	if n > MaxSourceBytes {
		return buf, "prefix_sha256:" + sha256Hex(buf), size, nil
	}
	return buf, "sha256:" + sha256Hex(buf), size, nil
}

func admissionReadLimit(size int64) int {
	if size < MaxSourceBytes {
		return int(size) + 1
	}
	return MaxSourceBytes + 1
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hashManifest(rows []manifestRow) string {
	ordered := append([]manifestRow(nil), rows...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].digest != ordered[j].digest {
			return ordered[i].digest < ordered[j].digest
		}
		if ordered[i].size != ordered[j].size {
			return ordered[i].size < ordered[j].size
		}
		if ordered[i].status != ordered[j].status {
			return ordered[i].status < ordered[j].status
		}
		if ordered[i].findingCount != ordered[j].findingCount {
			return ordered[i].findingCount < ordered[j].findingCount
		}
		return ordered[i].adjudication < ordered[j].adjudication
	})

	digester := sha256.New()
	for _, row := range ordered {
		// A hash.Hash write never returns an error.
		_, _ = fmt.Fprintf(digester, "%s\x00%d\x00%s\x00%d\x00%s\x00",
			row.digest, row.size, row.status, row.findingCount, row.adjudication)
	}
	return hex.EncodeToString(digester.Sum(nil))
}

func peakRSSBytes() (int64, error) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, fmt.Errorf("read peak RSS: %w", err)
	}
	// Maxrss is bytes on darwin and kilobytes on linux.
	if runtime.GOOS == "linux" {
		return ru.Maxrss * 1024, nil
	}
	return ru.Maxrss, nil
}

func logCorpusPass(t *testing.T, passNumber int, pass corpusPass) {
	t.Helper()
	durations := append([]time.Duration(nil), pass.durations...)
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	t.Logf("measured pass %d corpus files/bytes: %d / %d", passNumber, pass.fileCount, pass.byteCount)
	t.Logf("measured pass %d analysis/end-to-end: %v / %v", passNumber, pass.analysisTotal, pass.endToEnd)
	t.Logf("measured pass %d per-file p50/p95/max: %v / %v / %v", passNumber,
		pct(durations, 50), pct(durations, 95), pct(durations, 100))
	t.Logf("measured pass %d allocated bytes: %d", passNumber, pass.allocBytes)
	t.Logf("measured pass %d process peak RSS bytes: %d", passNumber, pass.peakRSS)
	for s := StatusNotCandidate; s <= StatusPanic; s++ {
		t.Logf("measured pass %d status %-14s %d", passNumber, s.String()+":", pass.statuses[s])
	}
	t.Logf("measured pass %d finding count: %d", passNumber, len(pass.findings))
	t.Logf("measured pass %d manifest sha256: %s", passNumber, pass.manifestSHA)
}

func logCorpusSummary(t *testing.T, passes []corpusPass) {
	t.Helper()
	analysisTotals := make([]time.Duration, 0, len(passes))
	allDurations := make([]time.Duration, 0)
	for _, pass := range passes {
		analysisTotals = append(analysisTotals, pass.analysisTotal)
		allDurations = append(allDurations, pass.durations...)
	}
	sort.Slice(analysisTotals, func(i, j int) bool { return analysisTotals[i] < analysisTotals[j] })
	sort.Slice(allDurations, func(i, j int) bool { return allDurations[i] < allDurations[j] })
	medianTotal := pct(analysisTotals, 50)
	worstFile := pct(allDurations, 100)
	t.Logf("median analysis wall clock: %v (release budget %v)", medianTotal, corpusTotalBudget)
	t.Logf("worst per-file wall clock: %v (release budget %v)", worstFile, corpusPerFileBudget)
	t.Logf("go version: %s", runtime.Version())
	t.Logf("parser module: github.com/tdewolff/parse/v2 %s", moduleVersion("github.com/tdewolff/parse/v2"))
	t.Logf("GOOS/GOARCH/NumCPU: %s / %s / %d", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
}

func moduleVersion(path string) string {
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, dep := range info.Deps {
			if dep.Path == path {
				if dep.Replace != nil && dep.Replace.Version != "" {
					return dep.Replace.Version
				}
				if dep.Version != "" {
					return dep.Version
				}
			}
		}
	}

	repoRoot, err := repositoryRoot()
	if err != nil {
		return "unknown"
	}
	data, err := os.ReadFile(filepath.Join(repoRoot, "go.mod")) // #nosec G304 -- path is anchored at this source file
	if err != nil {
		return "unknown"
	}
	fields := strings.Fields(string(data))
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == path {
			return fields[i+1]
		}
	}
	return "unknown"
}

func repositoryRoot() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate repository root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..")), nil
}

func pct(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	idx := (p*len(sorted)+99)/100 - 1
	return sorted[idx]
}
