// Command domlog-stream turns local copies of a host's domlogs into an
// anonymized record stream for crawl-detector calibration.
//
//	domlog-stream convert --salt-file SALT --registry registry.json \
//	    [--new-registry] --inventory inventory.json [--labels labels.json] \
//	    [--bot-evidence bots.json] --out records.jsonl.gz \
//	    --volume-out volume.jsonl.gz --manifest manifest.json
//
// Every line is parsed by the crawl detector's own record parser and
// canonicalized by its identity contract. Records keep logged time and
// order, status, request class, Referer class, claimed bot identity with
// its historical verified-bot proof, and operator labels; sites, accounts,
// client bindings and L1/L2 keys become salted pseudonyms that keep
// equality and hierarchy, and a pseudonym two names would share is refused. No target, query
// value, address, user agent or Referer is written. Outputs are staged and
// published only after every input converted; the manifest, which records
// input and output digests and per-site coverage, is published last as
// the bundle's completion marker. The salt file is created on first use
// (mode 0600) and is shared with scripts/finding-stream so the two streams
// join; the identity registry beside it records every site, account and
// episode pseudonym the salt has issued across bundles. A run that creates
// the salt starts its registry; a salt that already exists without one
// needs --new-registry once, and a lost registry stops conversion rather
// than start over. Collection is a read-only copy of the logs; nothing
// here runs on the monitored host.
package main

import (
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/crawlid"
	"github.com/pidginhost/csm/internal/crawlreplay"
)

// cliError is a fixed message: a refusal never repeats a path, a name or
// input bytes.
type cliError string

func (e cliError) Error() string { return string(e) }

const (
	errUsage           cliError = "usage: domlog-stream convert --salt-file SALT --registry FILE [--new-registry] --inventory FILE [--labels FILE] [--bot-evidence FILE] --out FILE --volume-out FILE --manifest FILE"
	errInventory       cliError = "inventory is invalid"
	errLabels          cliError = "labels are invalid"
	errInput           cliError = "a log copy could not be read"
	errInputIdentity   cliError = "a log copy is not a stable regular file or duplicates another copy"
	errOutputs         cliError = "an output already exists or cannot be written"
	errSaltUnsafe      cliError = "salt file must be a private regular file"
	errSaltShort       cliError = "salt file is shorter than 32 bytes"
	errDirtyBuild      cliError = "tool revision unknown or modified: build from a clean checkout with go build"
	errCollision       cliError = "two distinct names share a pseudonym under this salt"
	errRegistry        cliError = "identity registry is busy, invalid, not private or not for this salt"
	errRegistryPlace   cliError = "identity registry must be in the same directory as the salt"
	errRegistryMissing cliError = "identity registry is missing for an existing salt; restore it, or pass --new-registry if this salt never had one"
	errBotEvidence     cliError = "bot evidence is invalid"
)

func readBuildRevision() crawlreplay.ToolRevision {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return crawlreplay.ToolRevision{Dirty: true}
	}
	t := crawlreplay.ToolRevision{GoVersion: info.GoVersion, Dirty: true}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			t.Revision = s.Value
		case "vcs.modified":
			t.Dirty = s.Value != "false"
		}
	}
	return t
}

// env is what tests replace: the file system, the clock that bounds valid
// log times, the build stamp a manifest records and, to force collisions,
// the pseudonym digest (nil: HMAC-SHA256 under the salt).
type env struct {
	fs       fileSystem
	now      func() time.Time
	revision func() crawlreplay.ToolRevision
	digest   func(kind string, value []byte) [sha256.Size]byte
}

func defaultEnv() env { return env{fs: osFS{}, now: time.Now, revision: readBuildRevision} }

type options struct {
	salt, registry, inventory, labels, bots, out, volumeOut, manifest string
	newRegistry                                                       bool
}

// run is the testable entry point.
func run(args []string, stdout io.Writer, e env) error {
	if len(args) == 0 || args[0] != "convert" {
		return errUsage
	}
	var o options
	fs := flag.NewFlagSet("convert", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.salt, "salt-file", "", "")
	fs.StringVar(&o.registry, "registry", "", "")
	fs.BoolVar(&o.newRegistry, "new-registry", false, "")
	fs.StringVar(&o.inventory, "inventory", "", "")
	fs.StringVar(&o.labels, "labels", "", "")
	fs.StringVar(&o.bots, "bot-evidence", "", "")
	fs.StringVar(&o.out, "out", "", "")
	fs.StringVar(&o.volumeOut, "volume-out", "", "")
	fs.StringVar(&o.manifest, "manifest", "", "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 ||
		o.salt == "" || o.registry == "" || o.inventory == "" || o.out == "" || o.volumeOut == "" || o.manifest == "" {
		return errUsage
	}
	started := time.Now()
	now := e.now()
	tool := e.revision()
	if !tool.Clean() {
		return errDirtyBuild
	}
	for _, p := range []string{o.out, o.volumeOut, o.manifest} {
		if _, err := e.fs.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			return errOutputs
		}
	}
	// One registry per salt: it sits beside the salt, and a salt that
	// existed before this run keeps using the registry it already has.
	saltAbs, saltErr := filepath.Abs(o.salt)
	registryAbs, registryErr := filepath.Abs(o.registry)
	if saltErr != nil || registryErr != nil || filepath.Dir(saltAbs) != filepath.Dir(registryAbs) {
		return errRegistryPlace
	}
	salt, created, err := loadOrCreateSalt(e.fs, o.salt)
	if err != nil {
		return err
	}
	reg, err := openRegistry(e.fs, o.registry, saltFingerprint(salt))
	if err != nil {
		return err
	}
	defer reg.close()
	// Decided under the registry lock, so a concurrent first run cannot
	// slip a second registry in between.
	switch {
	case reg.existed && o.newRegistry:
		return errRegistry
	case !reg.existed && !created && !o.newRegistry:
		return errRegistryMissing
	}
	invBytes, err := readFile(e.fs, o.inventory)
	if err != nil {
		return errInventory
	}
	inv, err := parseInventory(invBytes)
	if err != nil {
		return err
	}
	// A period that has not ended yet cannot have been collected.
	if inv.Period.To.After(now) {
		return errInventory
	}
	m := crawlreplay.Manifest{
		FormatVersion: crawlreplay.ManifestVersion, StreamVersion: crawlreplay.StreamVersion, IdentityVersion: crawlid.Version,
		Tool: tool, SaltFingerprint: saltFingerprint(salt), Period: inv.Period.span(), Inventory: digestOf(invBytes),
	}
	var labels []labelRule
	if o.labels != "" {
		b, readErr := readFile(e.fs, o.labels)
		if readErr != nil {
			return errLabels
		}
		if labels, err = parseLabels(b, inv); err != nil {
			return err
		}
		d := digestOf(b)
		m.Labels = &d
	}
	ps := newPseudonyms(salt, e.digest)
	c := newConverter(e.fs, inv, labels, ps, now)
	if o.bots != "" {
		b, readErr := readFile(e.fs, o.bots)
		if readErr != nil {
			return errBotEvidence
		}
		if c.bots, err = parseBotEvidence(b); err != nil {
			return err
		}
		m.BotEvidence = &crawlreplay.BotEvidenceRef{Digest: digestOf(b), D2Revision: c.bots.D2Revision, ConfigSHA256: c.bots.ConfigSHA256}
	}
	// Refuse a site or account pseudonym collision, within this inventory
	// or with an earlier bundle, before any log is read.
	for _, s := range inv.Sites {
		_, siteErr := ps.site(s.Name)
		_, accountErr := ps.account(s.Account)
		if errors.Join(siteErr, accountErr) != nil {
			return errCollision
		}
	}
	if _, err = reg.add(ps.named); err != nil {
		return err
	}
	records, err := newStaged(e.fs, o.out)
	if err != nil {
		return err
	}
	volume, err := newStaged(e.fs, o.volumeOut)
	if err != nil {
		_ = records.discard()
		return err
	}
	fail := func(err error) error {
		_ = records.discard()
		_ = volume.discard()
		return err
	}
	for _, s := range inv.Sites {
		rows, sm, inputs, convErr := c.convertSite(s, records)
		if convErr != nil {
			return fail(convErr)
		}
		for _, v := range rows {
			if writeErr := crawlreplay.WriteRow(volume, v); writeErr != nil {
				return fail(errOutputs)
			}
		}
		volume.rows += int64(len(rows))
		records.rows += sm.Records
		m.Sites = append(m.Sites, sm)
		m.Inputs = append(m.Inputs, inputs...)
	}
	// Episode pseudonyms are issued as labels match; check them under the
	// same lock before any output is published.
	if _, err = reg.add(ps.named); err != nil {
		return fail(err)
	}
	recOut, err := records.finish("records")
	if err != nil {
		return fail(err)
	}
	volOut, err := volume.finish("volume")
	if err != nil {
		return fail(err)
	}
	m.Outputs = []crawlreplay.Output{recOut, volOut}
	manifestBytes, err := crawlreplay.EncodeManifest(m)
	if err != nil {
		return fail(errOutputs)
	}
	manifestFile, err := newStaged(e.fs, o.manifest)
	if err != nil {
		return fail(err)
	}
	// Record the pseudonyms before publishing: a bundle must never exist
	// without its names in the registry, while a recorded name whose bundle
	// failed only reserves that name's own pseudonym.
	if err = reg.save(); err != nil {
		_ = manifestFile.discard()
		return fail(err)
	}
	if _, err := manifestFile.raw.Write(manifestBytes); err != nil {
		_ = manifestFile.discard()
		return fail(errOutputs)
	}
	if err := publish(e.fs, records, volume, manifestFile); err != nil {
		return err
	}
	var lines int64
	for _, cov := range m.Sites {
		lines += cov.Lines
	}
	elapsed := time.Since(started)
	fmt.Fprintf(stdout, "sites: %d\nlines: %d\nrecords: %d\nsalt fingerprint: %s\nmanifest: written\n", len(m.Sites), lines, recOut.Rows, m.SaltFingerprint)
	// Wall time per line includes reading, decompressing and writing: an
	// upper bound on parse cost for this machine, recorded with its shape.
	fmt.Fprintf(stdout, "elapsed: %s\nns/line: %d\nplatform: %s/%s cpus=%d %s\n", elapsed.Round(time.Millisecond),
		elapsed.Nanoseconds()/max(1, lines), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
	return nil
}

func digestOf(b []byte) crawlreplay.Digest {
	sum := sha256.Sum256(b)
	return crawlreplay.Digest{SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(b))}
}

// staged is one output written to a private temporary file beside its
// final path; gzip outputs compress on the way.
type staged struct {
	fs    fileSystem
	final string
	file  file
	raw   io.Writer // digest and count, after compression
	gz    *gzip.Writer
	hash  hash.Hash
	bytes *countingWriter
	rows  int64
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

func newStaged(fsys fileSystem, final string) (*staged, error) {
	f, err := fsys.CreateTemp(filepath.Dir(final), ".domlog-stream-*.tmp")
	if err != nil {
		return nil, errOutputs
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		_ = fsys.Remove(f.Name())
		return nil, errOutputs
	}
	h := sha256.New()
	cw := &countingWriter{}
	s := &staged{fs: fsys, final: final, file: f, hash: h, bytes: cw}
	s.raw = io.MultiWriter(f, h, cw)
	if filepath.Ext(final) == ".gz" {
		s.gz = gzip.NewWriter(s.raw)
	}
	return s, nil
}

func (s *staged) Write(p []byte) (int, error) {
	if s.gz != nil {
		return s.gz.Write(p)
	}
	return s.raw.Write(p)
}

func (s *staged) finish(kind string) (crawlreplay.Output, error) {
	if s.gz != nil {
		if err := s.gz.Close(); err != nil {
			return crawlreplay.Output{}, errOutputs
		}
	}
	if err := s.file.Sync(); err != nil {
		return crawlreplay.Output{}, errOutputs
	}
	return crawlreplay.Output{Kind: kind, SHA256: hex.EncodeToString(s.hash.Sum(nil)), Bytes: s.bytes.n, Rows: s.rows}, nil
}

// discard closes and removes the temporary. A removal failure leaves a
// private mode-0600 file. Publication reports it; an already failed run
// retains its original fixed error and leaves cleanup to the operator.
func (s *staged) discard() error {
	s.file.Close()
	return s.fs.Remove(s.file.Name())
}

// publish links every staged file to its final name, which refuses to
// replace an existing file, and the manifest last. On failure it removes
// what this run published, so no bundle exists without its manifest.
func publish(fsys fileSystem, files ...*staged) error {
	var done []string
	for _, s := range files {
		if err := s.file.Sync(); err != nil {
			break
		}
		if err := s.file.Close(); err != nil {
			break
		}
		if err := fsys.Link(s.file.Name(), s.final); err != nil {
			break
		}
		done = append(done, s.final)
	}
	cleanupFailed := false
	for _, s := range files {
		cleanupFailed = s.discard() != nil || cleanupFailed
	}
	if len(done) != len(files) || cleanupFailed {
		for _, p := range done {
			_ = fsys.Remove(p)
		}
		return errOutputs
	}
	return nil
}

func saltFingerprint(salt []byte) string {
	sum := sha256.Sum256(salt)
	return hex.EncodeToString(sum[:6])
}

// loadOrCreateSalt reads the salt, creating it when absent; created
// reports a salt this run made.
func loadOrCreateSalt(fsys fileSystem, path string) (salt []byte, created bool, err error) {
	salt, err = readSalt(fsys, path)
	if !errors.Is(err, os.ErrNotExist) {
		return salt, false, err
	}
	if err = fsys.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, errSaltUnsafe
	}
	salt = make([]byte, 32)
	if _, err = rand.Read(salt); err != nil {
		return nil, false, errSaltUnsafe
	}
	f, err := fsys.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		salt, err = readSalt(fsys, path)
		return salt, false, err
	}
	if err != nil {
		return nil, false, errSaltUnsafe
	}
	_, writeErr := f.Write(salt)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return nil, false, errSaltUnsafe
	}
	return salt, true, nil
}

func readSalt(fsys fileSystem, path string) ([]byte, error) {
	// Refuse a symlink, and never block opening a FIFO.
	f, err := fsys.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return nil, errSaltUnsafe
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errSaltUnsafe
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, errSaltUnsafe
	}
	if len(b) < 32 {
		return nil, errSaltShort
	}
	return b, nil
}

// cli runs the command and reports a refusal, always a fixed message, on
// stderr. It returns the process exit status.
func cli(args []string, stdout, stderr io.Writer, e env) int {
	if err := run(args, stdout, e); err != nil {
		fmt.Fprintln(stderr, "domlog-stream:", err)
		return 1
	}
	return 0
}

func main() { os.Exit(cli(os.Args[1:], os.Stdout, os.Stderr, defaultEnv())) }
