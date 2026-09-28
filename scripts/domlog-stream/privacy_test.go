package main

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

// privacyMarkers appear in every private input and in every injected
// error; none may reach an output, stdout or stderr.
var privacyMarkers = []string{"secret-site", "secretacct", "secret-file", "secret-target", "secret-value", "secret-agent",
	"secret-referer", "secret-episode", "secret-malformed", "secret-out", "secret-inventory", "secret-fault"}

const privacySalt = "salt-marker-0123456789abcdefghij"

// faultFS passes every operation to the real file system, counts calls
// per operation and fails the chosen call with an error that names a
// private path. It tracks open files to prove every descriptor is closed.
type faultFS struct {
	base   fileSystem
	failOp string
	failAt int

	mu     sync.Mutex
	counts map[string]int
	open   int
}

func newFaultFS(op string, at int) *faultFS {
	return &faultFS{base: osFS{}, failOp: op, failAt: at, counts: map[string]int{}}
}

func (f *faultFS) fault(op string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts[op]++
	if op == f.failOp && f.counts[op] == f.failAt {
		return &os.PathError{Op: op, Path: "/private/secret-fault/secret-site.example", Err: errors.New("secret-fault injected")}
	}
	return nil
}

func (f *faultFS) track(file file, err error) (file, error) {
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.open++
	f.mu.Unlock()
	return &faultFile{file: file, fs: f}, nil
}

func (f *faultFS) OpenFile(name string, flag int, perm os.FileMode) (file, error) {
	if err := f.fault("open"); err != nil {
		return nil, err
	}
	return f.track(f.base.OpenFile(name, flag, perm))
}

func (f *faultFS) CreateTemp(dir, pattern string) (file, error) {
	if err := f.fault("createtemp"); err != nil {
		return nil, err
	}
	return f.track(f.base.CreateTemp(dir, pattern))
}

func (f *faultFS) Lstat(name string) (os.FileInfo, error) {
	if err := f.fault("lstat"); err != nil {
		return nil, err
	}
	return f.base.Lstat(name)
}

func (f *faultFS) Link(oldname, newname string) error {
	if err := f.fault("link"); err != nil {
		return err
	}
	return f.base.Link(oldname, newname)
}

func (f *faultFS) Rename(oldname, newname string) error {
	if err := f.fault("rename"); err != nil {
		return err
	}
	return f.base.Rename(oldname, newname)
}

// Remove is cleanup, not a publication boundary: failing it could only
// leave a private temporary behind, which the test would then report.
func (f *faultFS) Remove(name string) error { return f.base.Remove(name) }

func (f *faultFS) MkdirAll(path string, perm os.FileMode) error {
	if err := f.fault("mkdir"); err != nil {
		return err
	}
	return f.base.MkdirAll(path, perm)
}

type faultFile struct {
	file
	fs     *faultFS
	closed bool
}

func (f *faultFile) Read(p []byte) (int, error) {
	if err := f.fs.fault("read"); err != nil {
		return 0, err
	}
	return f.file.Read(p)
}

func (f *faultFile) Write(p []byte) (int, error) {
	if err := f.fs.fault("write"); err != nil {
		return 0, err
	}
	return f.file.Write(p)
}

func (f *faultFile) Stat() (os.FileInfo, error) {
	if err := f.fs.fault("stat"); err != nil {
		return nil, err
	}
	return f.file.Stat()
}

func (f *faultFile) Sync() error {
	if err := f.fs.fault("sync"); err != nil {
		return err
	}
	return f.file.Sync()
}

func (f *faultFile) Chmod(mode os.FileMode) error {
	if err := f.fs.fault("chmod"); err != nil {
		return err
	}
	return f.file.Chmod(mode)
}

// Close releases the descriptor even when it reports a failure, as close(2)
// does, and counts each file once.
func (f *faultFile) Close() error {
	injected := f.fs.fault("close")
	err := f.file.Close()
	if !f.closed {
		f.closed = true
		f.fs.mu.Lock()
		f.fs.open--
		f.fs.mu.Unlock()
	}
	if injected != nil {
		return injected
	}
	return err
}

type privacyFixture struct {
	dir, registry string
	args          []string
	existing      map[string][]byte
}

// newPrivacyFixture writes inputs carrying every marker: names, target,
// query value, user agent, Referer, episode, file names and a malformed line.
func newPrivacyFixture(t *testing.T) privacyFixture {
	t.Helper()
	dir := t.TempDir()
	path := func(name string) string { return filepath.Join(dir, name) }
	logs := strings.Join([]string{
		`192.0.2.10 - - [26/Sep/2026:19:00:05 +0000] "GET /secret-target/?q=secret-value HTTP/1.1" 200 5 "https://secret-referer.example/x" "secret-agent"`,
		`secret-malformed line with /secret-target/?q=secret-value`,
		`192.0.2.11 - - [26/Sep/2026:19:00:06 +0000] "GET /secret-target/?q=secret-value HTTP/1.1" 200 5 "-" "secret-agent"`,
	}, "\n") + "\n"
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write([]byte(strings.ReplaceAll(logs, "19:00:0", "19:01:0"))); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	inventory := `{"period":{"from":"2026-09-26T19:00:00Z","to":"2026-09-26T20:00:00Z"},"sites":[{"name":"secret-site.example",
	  "account":"secretacct","aliases":["secret-site.example"],"logs":["` + path("secret-file-log") + `","` + path("secret-file-log.gz") + `"]}]}`
	labels := `{"labels":[{"site":"secret-site.example","from":"2026-09-26T19:00:00Z","to":"2026-09-26T20:00:00Z",
	  "label":"attack","episode":"secret-episode","name_prefixes":["q"]}]}`
	f := privacyFixture{dir: dir, registry: path("secret-registry.json"), existing: map[string][]byte{
		"salt": []byte(privacySalt), "secret-file-log": []byte(logs), "secret-file-log.gz": gz.Bytes(),
		"secret-inventory.json": []byte(inventory), "secret-labels.json": []byte(labels),
		"bots.json": []byte(googlebotEvidence), "keep.txt": []byte("an unrelated file in the output directory"),
	}}
	for name, data := range f.existing {
		if err := os.WriteFile(path(name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f.args = []string{"convert", "--salt-file", path("salt"), "--registry", f.registry, "--inventory", path("secret-inventory.json"),
		"--labels", path("secret-labels.json"), "--bot-evidence", path("bots.json"), "--out", path("secret-out.records.jsonl.gz"),
		"--volume-out", path("secret-out.volume.jsonl.gz"), "--manifest", path("secret-out.manifest.json")}
	return f
}

func assertNoPrivateText(t *testing.T, where string, data []byte, dir string) {
	t.Helper()
	for _, marker := range append(slices.Clone(privacyMarkers), dir, privacySalt, hex.EncodeToString([]byte(privacySalt))) {
		if bytes.Contains(data, []byte(marker)) {
			t.Fatalf("%s contains %q", where, marker)
		}
	}
	for _, op := range []string{"open ", "read ", "write ", "sync ", "close ", "chmod ", "link ", "rename ", "lstat ", "createtemp "} {
		if bytes.Contains(data, []byte(op+"/")) {
			t.Fatalf("%s carries file-system error text %q", where, op)
		}
	}
}

func TestConverterPrivacyFaults(t *testing.T) {
	// A clean run counts every boundary and fixes the registry a
	// successful conversion leaves.
	clean := newPrivacyFixture(t)
	counter := newFaultFS("", 0)
	e := testEnv()
	e.fs = counter
	var stdout, stderr bytes.Buffer
	if code := cli(clean.args, &stdout, &stderr, e); code != 0 || stderr.Len() != 0 {
		t.Fatalf("clean run exit %d stderr %q", code, stderr.String())
	}
	if counter.open != 0 {
		t.Fatalf("clean run left %d files open", counter.open)
	}
	assertNoPrivateText(t, "stdout", stdout.Bytes(), clean.dir)
	for _, name := range []string{"secret-out.records.jsonl.gz", "secret-out.volume.jsonl.gz"} {
		assertNoPrivateText(t, name, readGz(t, filepath.Join(clean.dir, name)), clean.dir)
	}
	for _, name := range []string{"secret-out.manifest.json", "secret-registry.json"} {
		assertNoPrivateText(t, name, mustRead(t, filepath.Join(clean.dir, name)), clean.dir)
	}
	wantRegistry := mustRead(t, clean.registry)
	var ops []string
	for op := range counter.counts {
		ops = append(ops, op)
	}
	slices.Sort(ops)
	for _, required := range []string{"open", "read", "write", "stat", "sync", "close", "chmod", "createtemp", "link", "rename", "lstat"} {
		if counter.counts[required] == 0 {
			t.Fatalf("clean run never performed %q; the fault sweep would not cover it", required)
		}
	}

	for _, op := range ops {
		for at := 1; at <= counter.counts[op]; at++ {
			f := newPrivacyFixture(t)
			fsys := newFaultFS(op, at)
			e := testEnv()
			e.fs = fsys
			var stdout, stderr bytes.Buffer
			code := cli(f.args, &stdout, &stderr, e)
			if fsys.open != 0 {
				t.Fatalf("%s #%d: %d files left open", op, at, fsys.open)
			}
			assertNoPrivateText(t, op+" stdout", stdout.Bytes(), f.dir)
			assertNoPrivateText(t, op+" stderr", stderr.Bytes(), f.dir)
			if code == 0 {
				if stderr.Len() != 0 {
					t.Fatalf("successful run wrote stderr: %q", stderr.String())
				}
				// Only a fault after the data is complete may pass, such as
				// closing a file already read or already published. It must
				// leave exactly the bundle a clean run publishes.
				assertSameBundle(t, op, at, clean, f)
				continue
			}
			fixed := slices.ContainsFunc(fixedErrors, func(c cliError) bool { return stderr.String() == "domlog-stream: "+string(c)+"\n" })
			if code != 1 || !fixed || stdout.Len() != 0 {
				t.Fatalf("%s #%d: exit %d stdout %q stderr %q, want one fixed error", op, at, code, stdout.String(), stderr.String())
			}
			assertNoPrivateText(t, op+" stderr", stderr.Bytes(), f.dir)
			if fsys.open != 0 {
				t.Fatalf("%s #%d: %d files left open", op, at, fsys.open)
			}
			entries, readErr := os.ReadDir(f.dir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, entry := range entries {
				name := entry.Name()
				_, existed := f.existing[name]
				switch {
				case existed:
					if got := mustRead(t, filepath.Join(f.dir, name)); !bytes.Equal(got, f.existing[name]) {
						t.Fatalf("%s #%d: existing %s changed", op, at, name)
					}
				case name == "secret-registry.json.lock":
				case name == "secret-registry.json":
					// The registry is written before publication; a later
					// failure keeps exactly the names this inventory holds.
					if !bytes.Equal(mustRead(t, filepath.Join(f.dir, name)), wantRegistry) {
						t.Fatalf("%s #%d: registry differs from a successful run's", op, at)
					}
				default:
					t.Fatalf("%s #%d: failure left %s", op, at, name)
				}
			}
		}
	}
}

func assertSameBundle(t *testing.T, op string, at int, clean, f privacyFixture) {
	t.Helper()
	for _, name := range []string{"secret-out.records.jsonl.gz", "secret-out.volume.jsonl.gz"} {
		if !bytes.Equal(readGz(t, filepath.Join(f.dir, name)), readGz(t, filepath.Join(clean.dir, name))) {
			t.Fatalf("tolerated %s #%d changed %s", op, at, name)
		}
	}
	m, err := crawlreplay.DecodeManifest(mustRead(t, filepath.Join(f.dir, "secret-out.manifest.json")))
	if err != nil {
		t.Fatalf("tolerated %s #%d left a bad manifest: %v", op, at, err)
	}
	if _, err = crawlreplay.ValidateBundle(crawlreplay.BundleInput{Manifest: m,
		Volume:  bytes.NewReader(mustRead(t, filepath.Join(f.dir, "secret-out.volume.jsonl.gz"))),
		Records: bytes.NewReader(mustRead(t, filepath.Join(f.dir, "secret-out.records.jsonl.gz")))}, 1, crawlreplay.BundleVisitor{}); err != nil {
		t.Fatalf("tolerated %s #%d left an inconsistent bundle: %v", op, at, err)
	}
	if !bytes.Equal(mustRead(t, f.registry), mustRead(t, clean.registry)) {
		t.Fatalf("tolerated %s #%d changed the registry", op, at)
	}
}

// fixedErrors is every message the command may print.
var fixedErrors = []cliError{errUsage, errInventory, errLabels, errInput, errInputIdentity, errOutputs, errSaltUnsafe,
	errSaltShort, errDirtyBuild, errCollision, errRegistry, errBotEvidence}

func TestCLIReportsFixedErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no command":    {},
		"unknown flag":  {"convert", "--secret-value", "/private/secret-file"},
		"missing flags": {"convert", "--inventory", "/private/secret-inventory.json"},
		"stray operand": {"convert", "secret-target"},
	} {
		var stdout, stderr bytes.Buffer
		if code := cli(args, &stdout, &stderr, defaultEnv()); code != 1 || stderr.String() != "domlog-stream: "+string(errUsage)+"\n" || stdout.Len() != 0 {
			t.Errorf("%s: exit %d stdout %q stderr %q", name, code, stdout.String(), stderr.String())
		}
	}
	// A test binary carries no clean source revision, so the real build
	// check refuses before any input or output is touched.
	f := newPrivacyFixture(t)
	var stdout, stderr bytes.Buffer
	if code := cli(f.args, &stdout, &stderr, defaultEnv()); code != 1 || stderr.String() != "domlog-stream: "+string(errDirtyBuild)+"\n" {
		t.Fatalf("unstamped build: exit %d stderr %q", code, stderr.String())
	}
	assertNoPrivateText(t, "stderr", stderr.Bytes(), f.dir)
}

// A persistent cleanup failure cannot be hidden behind a successful CLI exit.
// Leftovers must remain private; callers retain them for approved cleanup.
type cleanupFaultFS struct{ *faultFS }

func (f cleanupFaultFS) Remove(name string) error {
	return &os.PathError{Op: "remove", Path: name, Err: errors.New("secret-fault cleanup")}
}
func TestConverterReportsCleanupFailure(t *testing.T) {
	f := newPrivacyFixture(t)
	counter := newFaultFS("", 0)
	e := testEnv()
	e.fs = cleanupFaultFS{counter}
	var stdout, stderr bytes.Buffer
	if code := cli(f.args, &stdout, &stderr, e); code != 1 || stderr.String() != "domlog-stream: "+string(errOutputs)+"\n" || stdout.Len() != 0 {
		t.Fatalf("cleanup failure: exit %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
	if counter.open != 0 {
		t.Fatalf("cleanup failure left %d descriptors", counter.open)
	}
	assertNoPrivateText(t, "cleanup error", stderr.Bytes(), f.dir)
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	leftovers := 0
	for _, entry := range entries {
		path := filepath.Join(f.dir, entry.Name())
		if before, ok := f.existing[entry.Name()]; ok {
			if !bytes.Equal(mustRead(t, path), before) {
				t.Fatal("cleanup changed an existing input")
			}
			continue
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("cleanup left public or irregular file %s", entry.Name())
		}
		raw := mustRead(t, path)
		if len(raw) > 1 && raw[0] == 0x1f && raw[1] == 0x8b {
			raw = readGz(t, path)
		}
		assertNoPrivateText(t, "cleanup leftover", raw, f.dir)
		if strings.HasSuffix(entry.Name(), ".tmp") {
			leftovers++
		}
	}
	if leftovers == 0 {
		t.Fatal("cleanup fault did not leave any temporary")
	}
}
