//go:build linux || darwin

package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/yara"
)

// stampedOS serves the real filesystem but reports the change time and owner
// a test assigns to each base name. The kernel sets ctime when a file is
// written, so without this a test cannot build files planted hours apart.
type stampedOS struct {
	realOS
	dir      string
	stamps   map[string]time.Time
	fallback time.Time
	uids     map[string]uint32
	reads    atomic.Int64
}

type stampedInfo struct {
	os.FileInfo
	stat *syscall.Stat_t
}

func (i stampedInfo) Sys() any { return i.stat }

func (o *stampedOS) Lstat(name string) (os.FileInfo, error) {
	info, err := o.realOS.Lstat(name)
	if err != nil {
		return nil, err
	}
	return o.stamp(name, info), nil
}

func (o *stampedOS) stamp(name string, info os.FileInfo) os.FileInfo {
	base := filepath.Base(name)
	at, stamped := o.stamps[base]
	if !stamped && !o.fallback.IsZero() {
		at, stamped = o.fallback, true
	}
	uid, owned := o.uids[base]
	if !stamped && !owned {
		return info
	}
	st := *info.Sys().(*syscall.Stat_t)
	if stamped {
		setStatChangeTime(&st, at)
	}
	if owned {
		st.Uid = uid
	}
	return stampedInfo{FileInfo: info, stat: &st}
}

// Open counts every content read; the swept directory itself is not one.
func (o *stampedOS) Open(name string) (*os.File, error) {
	if name != o.dir {
		o.reads.Add(1)
	}
	return o.realOS.Open(name)
}

func useStampedOS(t *testing.T, fs *stampedOS) {
	t.Helper()
	prev := osFS
	prevStat := companionFileStat
	osFS = fs
	companionFileStat = func(file *os.File) (os.FileInfo, error) {
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		return fs.stamp(file.Name(), info), nil
	}
	t.Cleanup(func() { osFS = prev; companionFileStat = prevStat })
}

func useCompanionYARA(t *testing.T, b yara.Backend) {
	t.Helper()
	yara.SetActive(b)
	t.Cleanup(func() { yara.SetActive(nil) })
}

func withCompanionQueue(t *testing.T) *companionSweepQueue {
	t.Helper()
	prev := companionSweeps
	companionSweeps = newCompanionSweepQueue()
	t.Cleanup(func() { companionSweeps = prev })
	return companionSweeps
}

func writeKitFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func kitDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "theme", "assets")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func anchorAt(t *testing.T, path string, now time.Time) companionAnchor {
	t.Helper()
	info, err := osFS.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := newCompanionAnchor(path, info, now)
	if !ok {
		t.Fatalf("no anchor for %s", path)
	}
	return a
}

func findingsByCheck(findings []alert.Finding, check string) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

func companionLine(details, name string) string {
	quoted := strconv.QuoteToASCII(name)
	for _, line := range strings.Split(details, "\n") {
		if strings.HasPrefix(line, "- "+quoted+":") {
			return line
		}
	}
	return ""
}

type countingYARABackend struct {
	scans atomic.Int64
}

func (b *countingYARABackend) ScanFile(string, int) []yara.Match { return nil }
func (b *countingYARABackend) ScanBytes(data []byte) []yara.Match {
	matches, _ := b.ScanBytesChecked(data)
	return matches
}
func (b *countingYARABackend) ScanBytesChecked([]byte) ([]yara.Match, error) {
	b.scans.Add(1)
	return nil, nil
}
func (b *countingYARABackend) RuleCount() int { return 1 }
func (b *countingYARABackend) Reload() error  { return nil }

// A kit is planted in one session: the members a scanner recognised are
// reported by that scanner, and the rest -- loaders no rule matches, an
// encrypted blob, a binary dropper, an access file -- are named together in
// one finding about the detected file. Files written outside the session and
// harmless asset types are left out.
func TestCompanionSweepReportsFilesPlantedWithTheDetection(t *testing.T) {
	dir := kitDir(t)
	planted := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	fs := &stampedOS{dir: dir, stamps: map[string]time.Time{
		"loader-1.php": planted,
		"loader-2.php": planted.Add(2 * time.Second),
		"loader-3.php": planted.Add(3 * time.Second),
		"payload.php":  planted.Add(4 * time.Second),
		"blob":         planted.Add(5 * time.Second),
		"tool":         planted.Add(6 * time.Second),
		"pack":         planted.Add(7 * time.Second),
		".htaccess":    planted.Add(8 * time.Minute),
		"style.css":    planted.Add(9 * time.Second),
		"old.php":      planted.Add(-2 * time.Hour),
		"late.php":     planted.Add(companionPlantWindow + time.Second),
	}}
	anchor := writeKitFile(t, dir, "loader-1.php", []byte("<?php // detected\n"))
	writeKitFile(t, dir, "loader-2.php", []byte("<?php $x = 1;\n"))
	writeKitFile(t, dir, "loader-3.php", []byte("<?php $f='base'.'64_decode'; eval($f($_GET['c'])); ?>"))
	writeKitFile(t, dir, "payload.php", []byte("dormant malware"))
	blob := writeKitFile(t, dir, "blob", []byte(strings.Repeat("\x9c\x13\xa7\x51", 128)))
	// A dropper binary often carries the PHP it writes; it is still a binary.
	writeKitFile(t, dir, "tool", append([]byte("\x7fELF\x02\x01\x01"), []byte("\x00\x00<?php echo 1;\n")...))
	writeKitFile(t, dir, "pack", append([]byte("PK\x03\x04"), make([]byte, 64)...))
	writeKitFile(t, dir, ".htaccess", []byte("Options -Indexes\n"))
	writeKitFile(t, dir, "style.css", []byte("body { margin: 0; }\n"))
	writeKitFile(t, dir, "old.php", []byte("<?php $y = 2;\n"))
	writeKitFile(t, dir, "late.php", []byte("<?php $z = 3;\n"))
	backdated := time.Date(2023, 3, 14, 9, 0, 0, 0, time.UTC)
	if err := os.Chtimes(blob, backdated, backdated); err != nil {
		t.Fatal(err)
	}
	useStampedOS(t, fs)
	useCompanionYARA(t, &deepYARATestBackend{})

	findings := sweepCompanions(context.Background(), &config.Config{}, anchorAt(t, anchor, time.Now()))

	yaraHits := findingsByCheck(findings, "yara_match_scheduled")
	if len(yaraHits) != 1 || yaraHits[0].FilePath != filepath.Join(dir, "payload.php") {
		t.Fatalf("YARA findings = %+v, want one for payload.php", yaraHits)
	}
	if yaraHits[0].ContentSHA256 == "" || yaraHits[0].DetectLogic == "" {
		t.Fatalf("YARA finding lacks its content fingerprint: %+v", yaraHits[0])
	}
	var phpHits int
	for _, f := range findings {
		if f.FilePath == filepath.Join(dir, "loader-3.php") && (f.Check == "suspicious_php_content" || f.Check == "obfuscated_php") {
			phpHits++
		}
	}
	if phpHits != 1 {
		t.Fatalf("findings = %+v, want one PHP content finding for loader-3.php", findings)
	}

	companions := findingsByCheck(findings, "malware_companion_files")
	if len(companions) != 1 {
		t.Fatalf("companion findings = %+v, want exactly one", companions)
	}
	c := companions[0]
	if c.Severity != alert.High || !strings.Contains(c.Message, anchor) {
		t.Fatalf("companion finding = %+v, want High naming %s", c, anchor)
	}
	if !strings.Contains(c.Details, "Planted files: 5\n") {
		t.Errorf("details do not count five planted files:\n%s", c.Details)
	}
	wantKinds := map[string]string{
		"loader-2.php": "php",
		"blob":         "no extension",
		"tool":         "executable",
		"pack":         "archive",
		".htaccess":    "htaccess",
	}
	for name, kind := range wantKinds {
		line := companionLine(c.Details, name)
		if !strings.HasPrefix(line, "- "+strconv.QuoteToASCII(name)+": "+kind+",") {
			t.Errorf("line for %s = %q, want kind %q:\n%s", name, line, kind, c.Details)
		}
	}
	for _, name := range []string{"loader-1.php", "loader-3.php", "payload.php", "style.css", "old.php", "late.php"} {
		if line := companionLine(c.Details, name); line != "" {
			t.Errorf("%s must not be listed, got %q", name, line)
		}
	}
	if line := companionLine(c.Details, "blob"); !strings.Contains(line, "possible backdating") {
		t.Errorf("blob line %q does not flag its backdated modification time", line)
	}
	if line := companionLine(c.Details, "loader-2.php"); strings.Contains(line, "backdating") {
		t.Errorf("loader-2.php line %q flags a file whose times agree", line)
	}
}

// The access file in the detected directory is audited whatever its age: a
// kit often edits an existing one instead of writing a new one.
func TestCompanionSweepAuditsHtaccessOutsideTheWindow(t *testing.T) {
	dir := kitDir(t)
	planted := time.Now().Add(-3 * time.Hour)
	fs := &stampedOS{dir: dir, stamps: map[string]time.Time{
		"loader-1.php": planted,
		".htaccess":    planted.Add(-48 * time.Hour),
	}}
	anchor := writeKitFile(t, dir, "loader-1.php", []byte("<?php // detected\n"))
	writeKitFile(t, dir, ".htaccess", []byte("php_value auto_prepend_file /home/u/.cache/prelude\n"))
	useStampedOS(t, fs)

	findings := sweepCompanions(context.Background(), &config.Config{}, anchorAt(t, anchor, time.Now()))

	if got := countByCheck(findings, "htaccess_auto_prepend"); got != 1 {
		t.Fatalf("htaccess_auto_prepend = %d, want 1: %+v", got, findings)
	}
	if got := countByCheck(findings, "malware_companion_files"); got != 0 {
		t.Fatalf("an old access file is not a planted companion: %+v", findings)
	}
}

// A non-root writer can only create files it owns, so a file owned by
// someone else in a shared directory cannot be part of the same drop.
func TestCompanionSweepIgnoresFilesOfOtherOwners(t *testing.T) {
	dir := kitDir(t)
	planted := time.Now().Add(-3 * time.Hour)
	fs := &stampedOS{dir: dir, stamps: map[string]time.Time{
		"loader-1.php": planted,
		"mine.php":     planted.Add(time.Second),
		"theirs.php":   planted.Add(time.Second),
	}, uids: map[string]uint32{
		"theirs.php": uint32(os.Getuid()) + 1, // #nosec G115 -- test uid is small and non-negative
	}}
	anchor := writeKitFile(t, dir, "loader-1.php", []byte("<?php // detected\n"))
	writeKitFile(t, dir, "mine.php", []byte("<?php $a = 1;\n"))
	writeKitFile(t, dir, "theirs.php", []byte("<?php $b = 2;\n"))
	useStampedOS(t, fs)

	findings := findingsByCheck(sweepCompanions(context.Background(), &config.Config{}, anchorAt(t, anchor, time.Now())), "malware_companion_files")

	if len(findings) != 1 || companionLine(findings[0].Details, "mine.php") == "" {
		t.Fatalf("findings = %+v, want mine.php listed", findings)
	}
	if companionLine(findings[0].Details, "theirs.php") != "" {
		t.Fatalf("a file of another owner was listed:\n%s", findings[0].Details)
	}
	if got := fs.reads.Load(); got != 1 {
		t.Fatalf("content reads = %d, want only mine.php read", got)
	}
}

// Symlinks are never followed: neither a file link, a directory link, nor a
// swept directory that is itself a link.
func TestCompanionSweepDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "assets")
	outside := filepath.Join(root, "outside")
	for _, d := range []string{dir, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	planted := time.Now().Add(-3 * time.Hour)
	fs := &stampedOS{dir: dir, fallback: planted.Add(time.Second), stamps: map[string]time.Time{
		"loader-1.php": planted,
	}}
	anchor := writeKitFile(t, dir, "loader-1.php", []byte("<?php // detected\n"))
	target := writeKitFile(t, outside, "payload", []byte("dormant malware"))
	// Read and listed only if the symlinked directory below were followed.
	writeKitFile(t, outside, "extra.php", []byte("<?php $x = 1;\n"))
	if err := os.Symlink(target, filepath.Join(dir, "link.php")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linkdir")); err != nil {
		t.Fatal(err)
	}
	useStampedOS(t, fs)
	useCompanionYARA(t, &deepYARATestBackend{})

	findings := sweepCompanions(context.Background(), &config.Config{}, anchorAt(t, anchor, time.Now()))
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none through symlinks", findings)
	}
	if got := fs.reads.Load(); got != 0 {
		t.Fatalf("content reads = %d, want none", got)
	}

	linked := filepath.Join(root, "linked")
	if err := os.Symlink(outside, linked); err != nil {
		t.Fatal(err)
	}
	fs.dir = linked
	linkedAnchor := anchorAt(t, filepath.Join(linked, "payload"), time.Now())
	if findings := sweepCompanions(context.Background(), &config.Config{}, linkedAnchor); len(findings) != 0 {
		t.Fatalf("findings = %+v, want no sweep of a symlinked directory", findings)
	}
	if got := fs.reads.Load(); got != 0 {
		t.Fatalf("content reads = %d after a symlinked directory, want none", got)
	}
}

// Planting one detectable file in a huge directory must not buy the attacker
// a content scan of every entry: only files changed in the window are read.
func TestCompanionSweepOfLargeDirectoryWithoutPlantsReadsNothing(t *testing.T) {
	dir := kitDir(t)
	planted := time.Now().Add(-3 * time.Hour)
	fs := &stampedOS{dir: dir, fallback: planted.Add(-2 * time.Hour), stamps: map[string]time.Time{
		"loader-1.php": planted,
	}}
	anchor := writeKitFile(t, dir, "loader-1.php", []byte("<?php // detected\n"))
	for i := 0; i < 3000; i++ {
		writeKitFile(t, dir, fmt.Sprintf("f%04d.php", i), []byte("<?php\n"))
	}
	useStampedOS(t, fs)
	backend := &countingYARABackend{}
	useCompanionYARA(t, backend)

	findings := sweepCompanions(context.Background(), &config.Config{}, anchorAt(t, anchor, time.Now()))

	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
	if got := fs.reads.Load(); got != 0 {
		t.Fatalf("content reads = %d, want none", got)
	}
	if got := backend.scans.Load(); got != 0 {
		t.Fatalf("YARA scans = %d, want none", got)
	}
}

// The PHP taint analyzer sees every planted file, as in the deep scan.
func TestCompanionSweepRunsPHPTaintOnPlantedFiles(t *testing.T) {
	dir := kitDir(t)
	planted := time.Now().Add(-3 * time.Hour)
	fs := &stampedOS{dir: dir, stamps: map[string]time.Time{
		"loader-1.php": planted,
		"fetch.php":    planted.Add(time.Second),
	}}
	anchor := writeKitFile(t, dir, "loader-1.php", []byte("<?php // detected\n"))
	writeKitFile(t, dir, "fetch.php", []byte("<?php remote marker"))
	useStampedOS(t, fs)
	enablePHPTaintConsumer(t)
	withPHPTaintAnalyzer(t, func(_ context.Context, src []byte) phptaint.Report {
		if !strings.Contains(string(src), "remote marker") {
			return phptaint.Report{Status: phptaint.StatusNotCandidate}
		}
		return phptaint.Report{Status: phptaint.StatusAnalyzed, TotalResults: 1, Results: []phptaint.Result{{
			Source: "curl_exec", Sink: "eval", Confidence: phptaint.ConfidenceHigh,
			Basis: phptaint.BasisAlwaysRemote, ResolutionOffset: -1,
		}}}
	})

	findings := sweepCompanions(context.Background(), &config.Config{}, anchorAt(t, anchor, time.Now()))

	taint := findingsByCheck(findings, "php_remote_taint")
	if len(taint) != 1 || taint[0].FilePath != filepath.Join(dir, "fetch.php") {
		t.Fatalf("findings = %+v, want one taint finding for fetch.php", findings)
	}
	if got := countByCheck(findings, "malware_companion_files"); got != 0 {
		t.Fatalf("a matched file was also listed as unmatched: %+v", findings)
	}
}

// The sweep is CPU and I/O work like a check, so it waits for the shared scan
// budget and gives up when its context ends while waiting.
func TestCompanionSweepWaitsForTheScanBudget(t *testing.T) {
	dir := kitDir(t)
	planted := time.Now().Add(-3 * time.Hour)
	fs := &stampedOS{dir: dir, stamps: map[string]time.Time{
		"loader-1.php": planted,
		"loader-2.php": planted.Add(time.Second),
	}}
	anchor := writeKitFile(t, dir, "loader-1.php", []byte("<?php // detected\n"))
	writeKitFile(t, dir, "loader-2.php", []byte("<?php $x = 1;\n"))
	useStampedOS(t, fs)

	ctx := withScanBudget(context.Background(), 1)
	held := scanBudgetFrom(ctx).acquire(ctx)
	defer held.release()
	ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()

	if findings := sweepCompanions(ctx, &config.Config{}, anchorAt(t, anchor, time.Now())); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none without a scan slot", findings)
	}
	if got := fs.reads.Load(); got != 0 {
		t.Fatalf("content reads = %d without a scan slot, want none", got)
	}
}

// One detection per plant window: a second kit member, a repeated alert or
// the quarantine of the same file must not sweep the directory again.
func TestCompanionSweepQueueClaimsOneSweepPerPlantWindow(t *testing.T) {
	dir := kitDir(t)
	other := kitDir(t)
	now := time.Now()
	planted := now.Add(-time.Hour)
	fs := &stampedOS{stamps: map[string]time.Time{
		"a.php": planted,
		"b.php": planted.Add(5 * time.Minute),
		"c.php": planted.Add(companionPlantWindow + time.Second),
		"d.php": planted,
	}}
	paths := map[string]string{}
	for _, name := range []string{"a.php", "b.php", "c.php"} {
		paths[name] = writeKitFile(t, dir, name, []byte("<?php\n"))
	}
	paths["d.php"] = writeKitFile(t, other, "d.php", []byte("<?php\n"))
	useStampedOS(t, fs)
	info := func(name string) os.FileInfo {
		i, err := osFS.Lstat(paths[name])
		if err != nil {
			t.Fatal(err)
		}
		return i
	}

	q := newCompanionSweepQueue()
	steps := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"a.php", now, true},
		{"b.php", now, false},
		{"c.php", now, true},
		{"d.php", now, true},
		{"a.php", now, false},
	}
	for i, s := range steps {
		if got := q.add(paths[s.name], info(s.name), s.at); got != s.want {
			t.Fatalf("step %d: add(%s) = %v, want %v", i, s.name, got, s.want)
		}
	}
	// Claims expire after their sweep starts. An undrained window must not
	// mint a second pending sweep just because the worker is behind.
	for len(q.pending) > 0 {
		q.next(now.Add(companionPlantWindow))
	}
	if !q.add(paths["a.php"], info("a.php"), now.Add(companionClaimTTL+2*companionPlantWindow)) {
		t.Fatal("completed claim did not expire")
	}
}

// A file caught as it is written may be the first member of its kit to land.
// Its sweep waits until the window closes, while an old detection queued
// later is not held behind it.
func TestCompanionSweepQueueWaitsForThePlantWindowToClose(t *testing.T) {
	dir := kitDir(t)
	other := kitDir(t)
	now := time.Now()
	fs := &stampedOS{stamps: map[string]time.Time{
		"fresh.php": now,
		"old.php":   now.Add(-time.Hour),
	}}
	fresh := writeKitFile(t, dir, "fresh.php", []byte("<?php\n"))
	old := writeKitFile(t, other, "old.php", []byte("<?php\n"))
	useStampedOS(t, fs)

	q := newCompanionSweepQueue()
	for _, path := range []string{fresh, old} {
		info, err := osFS.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !q.add(path, info, now) {
			t.Fatalf("add(%s) refused", path)
		}
	}
	if a, _, ok := q.next(now); !ok || a.path != old {
		t.Fatalf("next = %+v ok=%v, want the old detection first", a, ok)
	}
	if _, wait, ok := q.next(now); ok || wait != companionPlantWindow {
		t.Fatalf("next ok=%v wait=%s, want a wait of %s", ok, wait, companionPlantWindow)
	}
	if a, _, ok := q.next(now.Add(companionPlantWindow)); !ok || a.path != fresh {
		t.Fatalf("next = %+v ok=%v, want the fresh detection once its window closed", a, ok)
	}
	if _, wait, ok := q.next(now); ok || wait != 0 {
		t.Fatalf("empty queue: ok=%v wait=%s, want nothing to wait for", ok, wait)
	}
}

// Only a Critical finding that proves one present regular file malicious
// starts a sweep.
func TestQueueCompanionSweepsTakesConfirmedFileDetections(t *testing.T) {
	q := withCompanionQueue(t)
	root := t.TempDir()
	sub := func(name string) string {
		d := filepath.Join(root, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		return d
	}
	hit := writeKitFile(t, sub("hit"), "shell.php", []byte("<?php\n"))
	high := writeKitFile(t, sub("high"), "maybe.php", []byte("<?php\n"))
	other := writeKitFile(t, sub("other"), "perm.php", []byte("<?php\n"))
	linkDir := sub("link")
	link := filepath.Join(linkDir, "link.php")
	if err := os.Symlink(hit, link); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(sub("gone"), "gone.php")

	QueueCompanionSweeps([]alert.Finding{
		{Severity: alert.Critical, Check: "yara_match_realtime", FilePath: hit},
		{Severity: alert.High, Check: "yara_match_scheduled", FilePath: high},
		{Severity: alert.Critical, Check: "world_writable_php", FilePath: other},
		{Severity: alert.Critical, Check: "webshell", FilePath: gone},
		{Severity: alert.Critical, Check: "webshell", FilePath: link},
		{Severity: alert.Critical, Check: "webshell", FilePath: sub("dir")},
		{Severity: alert.Critical, Check: "webshell"},
	})

	if len(q.pending) != 1 || q.pending[0].path != hit {
		t.Fatalf("pending = %+v, want only %s", q.pending, hit)
	}
}

// A quarantine removes the file before any finding about it reaches the
// dispatcher, so the quarantine itself queues the sweep with the stat taken
// before the move. Mail spool quarantines are not tenant files.
func TestQuarantineQueuesCompanionSweepWithTheOriginalStat(t *testing.T) {
	withActionSink(t)
	q := withCompanionQueue(t)
	orig := quarantineTargetFn
	t.Cleanup(func() { quarantineTargetFn = orig })
	quarantineTargetFn = func(path, _ string, _ os.FileInfo, _ []byte) error { return os.Remove(path) }

	dir := kitDir(t)
	path := writeKitFile(t, dir, "shell.php", []byte("<?php\n"))
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = quarantineTarget(path, filepath.Join(t.TempDir(), "q", "shell.php"), info, quarantineMetadata(path, info, "webshell")); err != nil {
		t.Fatal(err)
	}
	if len(q.pending) != 1 || q.pending[0].path != path || !sameFileIdentity(q.pending[0].info, info) {
		t.Fatalf("pending = %+v, want %s with its pre-quarantine stat", q.pending, path)
	}

	spool := writeKitFile(t, kitDir(t), "1abcde-000001-AB-H", []byte("header"))
	spoolInfo, err := os.Lstat(spool)
	if err != nil {
		t.Fatal(err)
	}
	meta := quarantineMetadata(spool, spoolInfo, "spool")
	meta.SpoolDir = filepath.Dir(spool)
	if err = quarantineTarget(spool, filepath.Join(t.TempDir(), "q", "spool"), spoolInfo, meta); err != nil {
		t.Fatal(err)
	}
	if len(q.pending) != 1 {
		t.Fatalf("pending = %+v, a spool quarantine must not queue a sweep", q.pending)
	}
}

// Cleaning rewrites the file, and its change time with it, before the finding
// reaches the dispatcher. The cleaner queues the sweep with the stat it read
// first.
func TestCleaningQueuesCompanionSweepWithTheOriginalStat(t *testing.T) {
	withActionSink(t)
	restoreQuarantineDir(t)
	q := withCompanionQueue(t)

	path := writeKitFile(t, kitDir(t), "index.php", []byte("<?php\n\x00\x0b@include(base64_decode(\"ZXZpbA==\"));\necho 'ok';\n"))
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if result := CleanInfectedFile(path); !result.Cleaned {
		t.Fatalf("clean did not run: %+v", result)
	}
	if len(q.pending) != 1 || q.pending[0].path != path {
		t.Fatalf("pending = %+v, want %s", q.pending, path)
	}
	want, _ := changeTimeOf(before)
	if !q.pending[0].changed.Equal(want) {
		t.Fatalf("anchor change time = %s, want the pre-clean %s", q.pending[0].changed, want)
	}
}

// The worker sweeps what is due, hands the result to the normal finding path
// and stops with its context.
func TestRunCompanionSweepsEmitsAndStops(t *testing.T) {
	q := withCompanionQueue(t)
	dir := kitDir(t)
	planted := time.Now().Add(-3 * time.Hour)
	fs := &stampedOS{dir: dir, stamps: map[string]time.Time{
		"loader-1.php": planted,
		"loader-2.php": planted.Add(time.Second),
	}}
	anchor := writeKitFile(t, dir, "loader-1.php", []byte("<?php // detected\n"))
	writeKitFile(t, dir, "loader-2.php", []byte("<?php $x = 1;\n"))
	useStampedOS(t, fs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	emitted := make(chan []alert.Finding, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunCompanionSweeps(ctx, func() *config.Config { return &config.Config{} }, func(f []alert.Finding) { emitted <- f })
	}()
	QueueCompanionSweeps([]alert.Finding{{Severity: alert.Critical, Check: "webshell", FilePath: anchor}})

	select {
	case got := <-emitted:
		if len(findingsByCheck(got, "malware_companion_files")) != 1 {
			t.Fatalf("emitted %+v, want the companion finding", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no sweep result emitted")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop with its context")
	}
	if len(q.pending) != 0 {
		t.Fatalf("pending = %+v after the sweep", q.pending)
	}
}

// An account scan reports companions with its own results, at once and once
// per plant window, without touching the daemon's queue.
func TestCompanionSweepFindingsForAccountScan(t *testing.T) {
	q := withCompanionQueue(t)
	dir := kitDir(t)
	planted := time.Now().Add(-3 * time.Hour)
	fs := &stampedOS{dir: dir, stamps: map[string]time.Time{
		"loader-1.php": planted,
		"loader-4.php": planted.Add(time.Second),
		"blob":         planted.Add(2 * time.Second),
	}}
	first := writeKitFile(t, dir, "loader-1.php", []byte("<?php // detected\n"))
	second := writeKitFile(t, dir, "loader-4.php", []byte("<?php // detected\n"))
	writeKitFile(t, dir, "blob", []byte(strings.Repeat("\x9c\x13", 64)))
	useStampedOS(t, fs)

	findings := companionSweepFindings(context.Background(), &config.Config{}, []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", FilePath: first},
		{Severity: alert.Critical, Check: "suspicious_php_content", FilePath: second},
	})

	companions := findingsByCheck(findings, "malware_companion_files")
	if len(companions) != 1 || companionLine(companions[0].Details, "blob") == "" {
		t.Fatalf("findings = %+v, want one companion finding naming blob", findings)
	}
	if line := companionLine(companions[0].Details, "loader-4.php"); line != "" {
		t.Fatalf("a file with its own finding was listed as unmatched: %q", line)
	}
	if len(q.pending) != 0 {
		t.Fatalf("account scan queued daemon sweeps: %+v", q.pending)
	}
}

func TestCompanionSweepTriggersAreMalwareFileChecks(t *testing.T) {
	for name := range companionSweepTriggers {
		info, ok := LookupCheck(name)
		if !ok || info.Category != CategoryMalware {
			t.Errorf("trigger %q is not a registered malware check", name)
		}
	}
	info, ok := LookupCheck("malware_companion_files")
	if !ok || info.Category != CategoryMalware {
		t.Fatal("malware_companion_files is not registered as a malware check")
	}
	if companionSweepTriggers["malware_companion_files"] || autoQuarantineChecks["malware_companion_files"] {
		t.Fatal("a companion report must neither start a sweep nor be quarantined")
	}
}

// An operator's account scan carries the companion report in its own results.
func TestRunAccountScanReportsPlantedCompanions(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	docroot := filepath.Join(root, "acct", "public_html", "wp-content", "uploads")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatal(err)
	}
	shell := writeKitFile(t, docroot, "c99.php", []byte("<?php // known name\n"))
	writeKitFile(t, docroot, "blob", []byte(strings.Repeat("\x9c\x13", 64)))

	cfg := &config.Config{AccountRoots: []string{root}}
	findings := RunAccountScanWithOptions(context.Background(), cfg, nil, "acct", DefaultAccountScanOptions(cfg))

	if countByCheck(findings, "webshell") == 0 {
		t.Fatalf("findings = %+v, the scan did not detect %s", findings, shell)
	}
	companions := findingsByCheck(findings, "malware_companion_files")
	if len(companions) != 1 || companionLine(companions[0].Details, "blob") == "" {
		t.Fatalf("findings = %+v, want the companion report naming blob", findings)
	}
}

func TestCompanionFindingAttributesByPath(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	dir := filepath.Join(root, "alice", "public_html", "wp-content", "uploads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	planted := time.Now().Add(-3 * time.Hour)
	fs := &stampedOS{dir: dir, stamps: map[string]time.Time{
		"loader-1.php": planted,
		"blob":         planted.Add(time.Second),
	}}
	anchor := writeKitFile(t, dir, "loader-1.php", []byte("<?php // detected\n"))
	writeKitFile(t, dir, "blob", []byte(strings.Repeat("\x9c\x13", 64)))
	useStampedOS(t, fs)

	findings := findingsByCheck(sweepCompanions(context.Background(), &config.Config{}, anchorAt(t, anchor, time.Now())), "malware_companion_files")

	requireChecks(t, expectAttributed(t, findings, "alice"), "malware_companion_files")
}

// The cost of a sweep in a directory of many entries, on the production
// filesystem path. "quiet" is an attacker's cheapest shape: one detectable
// file among entries written outside the window, so only metadata is read.
// "planted" puts every entry in the window, so every entry is read and
// scanned, the cost the attacker pays by writing them. Run with:
//
//	scripts/go-linux.sh go test ./internal/checks -run XXX -bench BenchmarkCompanionSweep -benchtime 10x -benchmem
func BenchmarkCompanionSweep(b *testing.B) {
	for _, bc := range []struct {
		name    string
		entries int
		shift   time.Duration
	}{
		{"quiet_100k", 100000, -time.Hour},
		{"planted_10k", 10000, 0},
	} {
		b.Run(bc.name, func(b *testing.B) {
			dir := b.TempDir()
			for i := 0; i < bc.entries; i++ {
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%06d.php", i)), []byte("<?php\n$opts = get_option('active_plugins');\n"), 0o644); err != nil {
					b.Fatal(err)
				}
			}
			anchor := filepath.Join(dir, "f000000.php")
			info, err := os.Lstat(anchor)
			if err != nil {
				b.Fatal(err)
			}
			a, ok := newCompanionAnchor(anchor, info, time.Now())
			if !ok {
				b.Fatal("no anchor")
			}
			// Every entry was just written; shifting the anchor moves them all
			// out of its window.
			a.changed = a.changed.Add(bc.shift)
			ctx := withScanBudget(context.Background(), 1)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				findings := sweepCompanions(ctx, &config.Config{}, a)
				if bc.shift != 0 && len(findings) != 0 {
					b.Fatalf("quiet directory produced %d findings", len(findings))
				}
				if bc.shift == 0 && countByCheck(findings, "malware_companion_files") != 1 {
					b.Fatalf("planted directory produced %+v", findings)
				}
			}
		})
	}
}
