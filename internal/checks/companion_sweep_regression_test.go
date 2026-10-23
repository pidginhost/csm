//go:build linux || darwin

package checks

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

func TestCompanionQueueDeduplicatesRepeatedDetections(t *testing.T) {
	path := writeKitFile(t, kitDir(t), "shell.php", []byte("<?php\n"))
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	q := newCompanionSweepQueue()
	for i := 0; i < 10000; i++ {
		q.add(path, info, time.Now())
	}
	if len(q.pending) != 1 || len(q.pending[0].detected) > 1 {
		t.Fatalf("repeated detection retained %d anchors and %d duplicates", len(q.pending), len(q.pending[0].detected))
	}
}

func TestCompanionQueueSeparatesOwners(t *testing.T) {
	dir := kitDir(t)
	a := writeKitFile(t, dir, "a.php", []byte("<?php\n"))
	b := writeKitFile(t, dir, "b.php", []byte("<?php\n"))
	fs := &stampedOS{uids: map[string]uint32{"b.php": uint32(os.Getuid()) + 1}}
	useStampedOS(t, fs)
	q := newCompanionSweepQueue()
	for _, path := range []string{a, b} {
		info, err := osFS.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !q.add(path, info, time.Now()) {
			t.Fatalf("detection by another owner was suppressed: %s", path)
		}
	}
}

func TestCompanionReadRejectsRestoredMtimeRewrite(t *testing.T) {
	path := writeKitFile(t, kitDir(t), "file.php", []byte("original"))
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if err := os.WriteFile(path, []byte("replaced"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	data, note := readCompanionFile(path, before, 1024)
	if len(data) != 0 || note == "" {
		t.Fatalf("accepted rewritten file: %q, %q", data, note)
	}
}

func TestCompanionSweepRejectsSymlinkedAncestor(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "real", "assets")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	writeKitFile(t, dir, "shell.php", []byte("<?php\n"))
	writeKitFile(t, dir, "blob", []byte("companion"))
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	a := anchorAt(t, filepath.Join(root, "link", "assets", "shell.php"), time.Now())
	if got := sweepCompanions(context.Background(), &config.Config{}, a); len(got) != 0 {
		t.Fatalf("followed ancestor link: %+v", got)
	}
}

func TestCompanionSweepHonorsAccountByteLimit(t *testing.T) {
	dir := kitDir(t)
	path := writeKitFile(t, dir, "shell.php", []byte("<?php\n"))
	writeKitFile(t, dir, "payload.php", []byte("dormant malware"))
	useCompanionYARA(t, &deepYARATestBackend{})
	ctx := ContextWithScanOptions(context.Background(), AccountScanOptions{MaxFileBytes: 4})
	got := sweepCompanions(ctx, &config.Config{}, anchorAt(t, path, time.Now()))
	if countByCheck(got, "yara_match_scheduled") != 0 || countByCheck(got, "malware_companion_files") != 1 || countByCheck(got, "malware_companion_scan_incomplete") != 1 || !strings.Contains(got[0].Details, "larger than the scan limit") {
		t.Fatalf("account byte limit ignored: %+v", got)
	}
}

func TestCompanionSweepReportsTaintFailure(t *testing.T) {
	dir := kitDir(t)
	path := writeKitFile(t, dir, "shell.php", []byte("<?php\n"))
	writeKitFile(t, dir, "loader.php", []byte("<?php echo 'candidate';"))
	enablePHPTaintConsumer(t)
	withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report { return phptaint.Report{Status: phptaint.StatusTimeout} })
	got := sweepCompanions(context.Background(), &config.Config{}, anchorAt(t, path, time.Now()))
	if countByCheck(got, "php_taint_scan_incomplete") != 1 {
		t.Fatalf("analyzer failure was hidden: %+v", got)
	}
}

func TestRefusedCleaningDoesNotQueueCompanionSweep(t *testing.T) {
	withActionSink(t)
	restoreQuarantineDir(t)
	q := withCompanionQueue(t)
	path := writeKitFile(t, kitDir(t), "clean.php", []byte("<?php echo 'hello';\n"))
	if result := CleanInfectedFile(path); !result.Refused {
		t.Fatalf("expected refusal: %+v", result)
	}
	if len(q.pending) != 0 {
		t.Fatal("cleaning a benign file queued a malware sweep")
	}
}

type companionOversizeBackend struct {
	deepYARATestBackend
	t    *testing.T
	path string
	read []byte
}

func (b *companionOversizeBackend) ScanBytesChecked([]byte) ([]yara.Match, error) {
	if err := os.WriteFile(b.path, []byte("replacement!!!"), 0600); err != nil {
		b.t.Fatal(err)
	}
	return nil, yaraipc.ErrPayloadTooLarge
}
func (b *companionOversizeBackend) ScanFileChecked(path string, _ int) (yara.FileScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return yara.FileScanResult{}, err
	}
	b.read = data
	return yara.FileScanResult{Matches: []yara.Match{{RuleName: "example", Meta: map[string]string{"severity": "critical"}}}, ContentSHA256: fmt.Sprintf("%x", sha256.Sum256(data))}, nil
}

func TestCompanionYARAFallbackScansTheSelectedSnapshot(t *testing.T) {
	dir := kitDir(t)
	path := writeKitFile(t, dir, "shell.php", []byte("<?php\n"))
	payload := writeKitFile(t, dir, "payload.php", []byte("dormant malware"))
	backend := &companionOversizeBackend{t: t, path: payload}
	useCompanionYARA(t, backend)
	got := sweepCompanions(context.Background(), &config.Config{}, anchorAt(t, path, time.Now()))
	if string(backend.read) != "dormant malware" {
		t.Fatalf("YARA reopened mutable source: %q", backend.read)
	}
	hits := findingsByCheck(got, "yara_match_scheduled")
	if len(hits) != 1 || hits[0].ContentSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte("dormant malware"))) {
		t.Fatalf("wrong snapshot finding: %+v", hits)
	}
}

func TestCompanionAccountFindingsHaveTimestamps(t *testing.T) {
	dir := kitDir(t)
	path := writeKitFile(t, dir, "shell.php", []byte("<?php\n"))
	writeKitFile(t, dir, "blob", []byte("companion"))
	got := companionSweepFindings(context.Background(), &config.Config{}, []alert.Finding{{Severity: alert.Critical, Check: "webshell", FilePath: path}})
	if len(got) != 1 || got[0].Timestamp.IsZero() {
		t.Fatalf("account report has no timestamp: %+v", got)
	}
}

func TestCompanionSweepUsesCheckDeadline(t *testing.T) {
	dir := kitDir(t)
	path := writeKitFile(t, dir, "shell.php", []byte("<?php\n"))
	writeKitFile(t, dir, "loader.php", []byte("<?php echo 'candidate';"))
	original := timeoutForFunc
	timeoutForFunc = func(string) time.Duration { return 100 * time.Millisecond }
	t.Cleanup(func() { timeoutForFunc = original })
	enablePHPTaintConsumer(t)
	var remaining time.Duration
	withPHPTaintAnalyzer(t, func(ctx context.Context, _ []byte) phptaint.Report {
		deadline, _ := ctx.Deadline()
		remaining = time.Until(deadline)
		return phptaint.Report{Status: phptaint.StatusNotCandidate}
	})
	sweepCompanions(context.Background(), &config.Config{}, anchorAt(t, path, time.Now()))
	if remaining <= 0 || remaining > 100*time.Millisecond {
		t.Fatalf("scan did not inherit check budget: %s", remaining)
	}
}

func TestCompanionPendingClaimDoesNotExpireBeforeDrain(t *testing.T) {
	path := writeKitFile(t, kitDir(t), "shell.php", []byte("<?php\n"))
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	q := newCompanionSweepQueue()
	now := time.Now()
	q.add(path, info, now)
	q.add(path, info, now.Add(2*companionClaimTTL))
	if len(q.pending) != 1 {
		t.Fatalf("undrained window retained %d duplicate sweeps", len(q.pending))
	}
}

func TestCompanionOverlappingWindowsDoNotRepeatFindings(t *testing.T) {
	dir := kitDir(t)
	now := time.Now()
	first := writeKitFile(t, dir, "a.php", []byte("<?php\n"))
	second := writeKitFile(t, dir, "b.php", []byte("<?php\n"))
	writeKitFile(t, dir, "payload.php", []byte("dormant malware"))
	useStampedOS(t, &stampedOS{dir: dir, stamps: map[string]time.Time{
		"a.php": now.Add(-time.Hour), "b.php": now.Add(-time.Hour + 15*time.Minute), "payload.php": now.Add(-time.Hour + 7*time.Minute),
	}})
	useCompanionYARA(t, &deepYARATestBackend{})
	got := companionSweepFindings(context.Background(), &config.Config{}, []alert.Finding{
		{Check: "webshell", Severity: alert.Critical, FilePath: first}, {Check: "webshell", Severity: alert.Critical, FilePath: second},
	})
	if countByCheck(got, "yara_match_scheduled") != 1 {
		t.Fatalf("overlapping windows repeated a detection: %+v", got)
	}
}

func TestCompanionWorkerStreamsMatches(t *testing.T) {
	q := newCompanionSweepQueue()
	dir := kitDir(t)
	path := writeKitFile(t, dir, "anchor.php", []byte("<?php\n"))
	for i := 0; i < 2*companionReadDirBatch; i++ {
		writeKitFile(t, dir, fmt.Sprintf("p%04d.php", i), []byte("dormant malware"))
	}
	backend := &deepYARATestBackend{}
	useCompanionYARA(t, backend)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	q.add(path, info, time.Now())
	q.pending[0].due = time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var batches, hits int
	q.run(ctx, func() *config.Config { return &config.Config{} }, func(findings []alert.Finding) {
		batches++
		hits += countByCheck(findings, "yara_match_scheduled")
		if len(findings) > companionReadDirBatch {
			t.Errorf("buffered %d findings in one batch", len(findings))
		}
		if hits == 2*companionReadDirBatch {
			cancel()
		}
	})
	if batches < 2 || hits != 2*companionReadDirBatch {
		t.Fatalf("batches=%d hits=%d", batches, hits)
	}
}

func TestFailedQuarantineDoesNotQueueCompanionSweep(t *testing.T) {
	withActionSink(t)
	q := withCompanionQueue(t)
	path := writeKitFile(t, kitDir(t), "file.php", []byte("<?php\n"))
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	refused := errors.New("refused move")
	err = quarantineTargetWith(path, filepath.Join(t.TempDir(), "q", "file.php"), info, quarantineMetadata(path, info, "test"),
		func(string, string, os.FileInfo, []byte) error { return refused })
	if !errors.Is(err, refused) {
		t.Fatalf("move error = %v", err)
	}
	if len(q.pending) != 0 {
		t.Fatal("unsuccessful manual quarantine queued a sweep")
	}
}

func TestHtaccessCleaningQueuesOriginalCompanionTime(t *testing.T) {
	withActionSink(t)
	q := withCompanionQueue(t)
	dir := kitDir(t)
	path := writeKitFile(t, dir, ".htaccess", []byte("Options -Indexes\nphp_value auto_prepend_file /tmp/.cache.php\n"))
	previousRoots, previousBackup := fixHtaccessAllowedRoots, htaccessBackupDirRoot
	fixHtaccessAllowedRoots, htaccessBackupDirRoot = []string{dir}, t.TempDir()
	t.Cleanup(func() { fixHtaccessAllowedRoots, htaccessBackupDirRoot = previousRoots, previousBackup })
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := changeTimeOf(info)
	if result := CleanHtaccessFile(path); !result.Success {
		t.Fatalf("clean failed: %+v", result)
	}
	if len(q.pending) != 1 || !q.pending[0].changed.Equal(want) {
		t.Fatal("htaccess cleanup lost its pre-rewrite anchor")
	}
}

func TestCompanionReadRejectsRewriteDuringRead(t *testing.T) {
	path := writeKitFile(t, kitDir(t), "file.php", []byte("original"))
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	previous := companionFileStat
	t.Cleanup(func() { companionFileStat = previous })
	calls := 0
	companionFileStat = func(f *os.File) (os.FileInfo, error) {
		current, err := f.Stat()
		calls++
		if calls == 1 {
			time.Sleep(2 * time.Millisecond)
			if writeErr := os.WriteFile(path, []byte("replaced"), 0600); writeErr != nil {
				t.Fatal(writeErr)
			}
			if timeErr := os.Chtimes(path, info.ModTime(), info.ModTime()); timeErr != nil {
				t.Fatal(timeErr)
			}
		}
		return current, err
	}
	if data, note := readCompanionFile(path, info, 1024); len(data) != 0 || note == "" {
		t.Fatalf("accepted concurrent rewrite: %q %q", data, note)
	}
	if calls != 2 {
		t.Fatalf("descriptor snapshots = %d, want before and after reading", calls)
	}
}

func TestCompanionReadPinsDirectoryAndRejectsReplacements(t *testing.T) {
	for _, replacement := range []string{"file", "symlink", "fifo", "directory"} {
		t.Run(replacement, func(t *testing.T) {
			dir := kitDir(t)
			path := writeKitFile(t, dir, "file.php", []byte("original"))
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			pinned, err := openTenantDirectory(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = pinned.Close() }()
			if err = os.Rename(path, path+".saved"); err != nil {
				t.Fatal(err)
			}
			switch replacement {
			case "file":
				writeKitFile(t, dir, "file.php", []byte("replaced"))
			case "symlink":
				err = os.Symlink(path+".saved", path)
			case "fifo":
				err = unix.Mkfifo(path, 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan bool, 1)
			go func() {
				data, note := readCompanionFileFrom(context.Background(), pinned, path, info, 1024)
				done <- len(data) == 0 && note != ""
			}()
			select {
			case refused := <-done:
				if !refused {
					t.Fatal("accepted replacement")
				}
			case <-time.After(time.Second):
				t.Fatal("blocked opening replacement")
			}
		})
	}
	t.Run("parent swap", func(t *testing.T) {
		dir := kitDir(t)
		path := writeKitFile(t, dir, "file.php", []byte("original"))
		pinned, err := openTenantDirectory(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = pinned.Close() }()
		if err = os.Rename(dir, dir+".saved"); err != nil {
			t.Fatal(err)
		}
		outside := t.TempDir()
		writeKitFile(t, outside, "file.php", []byte("outside"))
		if err = os.Symlink(outside, dir); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if data, note := readCompanionFileFrom(context.Background(), pinned, path, info, 1024); len(data) != 0 || note == "" {
			t.Fatalf("read replacement directory: %q %q", data, note)
		}
	})
}

func TestCompanionConcurrentDetectionsAndShutdown(t *testing.T) {
	q := newCompanionSweepQueue()
	path := writeKitFile(t, kitDir(t), "shell.php", []byte("<?php\n"))
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		q.run(ctx, func() *config.Config { return &config.Config{} }, func([]alert.Finding) {})
	}()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				q.add(path, info, time.Now())
			}
		}()
	}
	wg.Wait()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sweeper did not stop")
	}
	if q.add(path, info, time.Now()) || len(q.pending) != 0 || len(q.claims) != 0 {
		t.Fatal("stopped queue retained work")
	}
}

type companionLstatCounter struct {
	realOS
	calls int
}

func (fs *companionLstatCounter) Lstat(path string) (os.FileInfo, error) {
	fs.calls++
	return fs.realOS.Lstat(path)
}

func TestCompanionCancelledAccountScanDoesNotCollectAnchors(t *testing.T) {
	path := writeKitFile(t, kitDir(t), "shell.php", []byte("<?php\n"))
	fs := &companionLstatCounter{}
	previous := osFS
	osFS = fs
	t.Cleanup(func() { osFS = previous })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	companionSweepFindings(ctx, &config.Config{}, []alert.Finding{{Check: "webshell", Severity: alert.Critical, FilePath: path}})
	if fs.calls != 0 {
		t.Fatalf("cancelled report made %d filesystem queries", fs.calls)
	}
}

func TestCompanionTimeoutReleasesBudget(t *testing.T) {
	dir := kitDir(t)
	path := writeKitFile(t, dir, "shell.php", []byte("<?php\n"))
	writeKitFile(t, dir, "loader.php", []byte("<?php echo 'candidate';"))
	previous := timeoutForFunc
	timeoutForFunc = func(string) time.Duration { return 30 * time.Millisecond }
	t.Cleanup(func() { timeoutForFunc = previous })
	enablePHPTaintConsumer(t)
	withPHPTaintAnalyzer(t, func(ctx context.Context, _ []byte) phptaint.Report {
		<-ctx.Done()
		return phptaint.Report{Status: phptaint.StatusTimeout}
	})
	ctx := withScanBudget(context.Background(), 1)
	got := sweepCompanions(ctx, &config.Config{}, anchorAt(t, path, time.Now()))
	if countByCheck(got, "check_timeout") != 1 || len(scanBudgetFrom(ctx).slots) != 0 {
		t.Fatalf("timeout lost or slot retained: %+v", got)
	}
}

func TestCompanionTimeoutWaitingForBudgetIsReported(t *testing.T) {
	path := writeKitFile(t, kitDir(t), "anchor.php", []byte("<?php\n"))
	previous := timeoutForFunc
	timeoutForFunc = func(string) time.Duration { return 30 * time.Millisecond }
	t.Cleanup(func() { timeoutForFunc = previous })
	ctx := withScanBudget(context.Background(), 1)
	occupied := scanBudgetFrom(ctx).acquire(ctx)
	defer occupied.release()
	got := sweepCompanions(ctx, &config.Config{}, anchorAt(t, path, time.Now()))
	if len(got) != 1 || got[0].Check != "check_timeout" || got[0].Timestamp.IsZero() {
		t.Fatalf("waiting for a scan slot silently lost the sweep: %+v", got)
	}
	if len(scanBudgetFrom(ctx).slots) != 1 {
		t.Fatal("sweep released another scan's slot")
	}
}

func TestCompanionSweepResultsDoNotScheduleAnotherSweep(t *testing.T) {
	q := newCompanionSweepQueue()
	dir := kitDir(t)
	now := time.Now()
	path := writeKitFile(t, dir, "anchor.php", []byte("<?php\n"))
	writeKitFile(t, dir, ".htaccess", []byte("dormant malware"))
	useStampedOS(t, &stampedOS{dir: dir, stamps: map[string]time.Time{"anchor.php": now.Add(-time.Hour), ".htaccess": now.Add(-48 * time.Hour)}})
	useCompanionYARA(t, &deepYARATestBackend{})
	info, err := osFS.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	q.add(path, info, now)
	a, _, ok := q.next(now)
	if !ok {
		t.Fatal("missing sweep")
	}
	var hits int
	sweepCompanionsTo(context.Background(), &config.Config{}, a, func(batch []alert.Finding) {
		hits += countByCheck(batch, "yara_match_scheduled")
		q.observe(batch, now)
		// The automatic response producer also submits the same pre-move stat.
		for _, f := range batch {
			if f.Check == "yara_match_scheduled" {
				info, err := osFS.Lstat(f.FilePath)
				if err != nil {
					t.Fatal(err)
				}
				q.add(f.FilePath, info, now)
			}
		}
	})
	if hits != 1 || len(q.pending) != 0 {
		t.Fatalf("hits=%d pending=%d", hits, len(q.pending))
	}
}

func TestCompanionReportsNeverRemediateUnmatchedFiles(t *testing.T) {
	q := withCompanionQueue(t)
	dir := kitDir(t)
	path := writeKitFile(t, dir, "anchor.php", []byte("<?php\n"))
	other := writeKitFile(t, dir, "loader.php", []byte("<?php echo 'keep';"))
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	cfg.AutoResponse.CleanHtaccess = true
	got := sweepCompanions(context.Background(), cfg, anchorAt(t, path, time.Now()))
	if len(got) != 1 || got[0].Check != "malware_companion_files" {
		t.Fatalf("unexpected report: %+v", got)
	}
	if actions := AutoQuarantineFiles(cfg, got); len(actions) != 0 {
		t.Fatalf("companion response: %+v", actions)
	}
	if data, err := os.ReadFile(other); err != nil || string(data) != "<?php echo 'keep';" {
		t.Fatalf("companion changed: %q %v", data, err)
	}
	if len(q.pending) != 0 {
		t.Fatal("report queued a recursive sweep")
	}
}

func TestCompanionYARAFailureIsVisibleForAnyFileKind(t *testing.T) {
	dir := kitDir(t)
	path := writeKitFile(t, dir, "shell.php", []byte("<?php\n"))
	writeKitFile(t, dir, "image.dat", []byte("unexamined content"))
	useCompanionYARA(t, &deepYARATestBackend{err: errors.New("worker unavailable")})
	got := sweepCompanions(context.Background(), &config.Config{}, anchorAt(t, path, time.Now()))
	if len(got) != 1 || got[0].Check != "malware_companion_scan_incomplete" || !strings.Contains(got[0].Details, "YARA could not scan it") {
		t.Fatalf("hidden scan failure: %+v", got)
	}
}

type companionSiblingOS struct {
	realOS
	dir    string
	opens  int
	cancel context.CancelFunc
}

func (fs *companionSiblingOS) Open(path string) (*os.File, error) {
	if path == fs.dir {
		fs.opens++
		if fs.cancel != nil {
			fs.cancel()
		}
	}
	return fs.realOS.Open(path)
}

func TestCompanionHtaccessSiblingScanIsBounded(t *testing.T) {
	for _, cancelDuringRead := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%t", cancelDuringRead), func(t *testing.T) {
			dir := kitDir(t)
			shield := "<FilesMatch \"\\.php$\">\nAllow from all\n</FilesMatch>\n"
			path := writeKitFile(t, dir, ".htaccess", []byte(strings.Repeat(shield, 20)))
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			pinned, err := openTenantDirectory(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = pinned.Close() }()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fs := &companionSiblingOS{dir: dir}
			if cancelDuringRead {
				fs.cancel = cancel
			}
			previous := osFS
			osFS = fs
			t.Cleanup(func() { osFS = previous })
			got, _ := scanCompanionFile(ctx, &config.Config{}, pinned, path, info, 1<<20)
			want := 20
			if cancelDuringRead {
				want = 0
			}
			if fs.opens != 1 || countByCheck(got, "htaccess_filesmatch_shield") != want {
				t.Fatalf("sibling scan opened %d times, want 1; shield findings = %d, want %d", fs.opens, countByCheck(got, "htaccess_filesmatch_shield"), want)
			}
		})
	}
}
