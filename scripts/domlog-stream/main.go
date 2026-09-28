// Command domlog-stream turns local copies of a host's domlogs into an
// anonymized record stream for crawl-detector calibration.
//
//	domlog-stream convert --salt-file SALT --registry registry.json \
//	    --inventory inventory.json [--labels labels.json] \
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
// episode pseudonym the salt has issued across bundles. Collection is a read-only
// copy of the logs; nothing here runs on the monitored host.
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
	errUsage         cliError = "usage: domlog-stream convert --salt-file SALT --registry FILE --inventory FILE [--labels FILE] [--bot-evidence FILE] --out FILE --volume-out FILE --manifest FILE"
	errInventory     cliError = "inventory is invalid"
	errLabels        cliError = "labels are invalid"
	errInput         cliError = "a log copy could not be read"
	errInputIdentity cliError = "a log copy is not a stable regular file or duplicates another copy"
	errOutputs       cliError = "an output already exists or cannot be written"
	errSaltUnsafe    cliError = "salt file must be a private regular file"
	errSaltShort     cliError = "salt file is shorter than 32 bytes"
	errDirtyBuild    cliError = "tool revision unknown or modified: build from a clean checkout with go build"
	errCollision     cliError = "two distinct names share a pseudonym under this salt"
	errRegistry      cliError = "identity registry is busy, invalid, not private or not for this salt"
	errBotEvidence   cliError = "bot evidence is invalid"
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

// env is what tests replace: the clock that bounds valid log times, the
// build stamp a manifest records and, to force collisions, the pseudonym
// digest (nil: HMAC-SHA256 under the salt).
type env struct {
	now      func() time.Time
	revision func() crawlreplay.ToolRevision
	digest   func(kind string, value []byte) [sha256.Size]byte
}

type options struct {
	salt, registry, inventory, labels, bots, out, volumeOut, manifest string
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
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			return errOutputs
		}
	}
	salt, err := loadOrCreateSalt(o.salt)
	if err != nil {
		return err
	}
	reg, err := openRegistry(o.registry, saltFingerprint(salt))
	if err != nil {
		return err
	}
	defer reg.close()
	invBytes, err := os.ReadFile(o.inventory) // #nosec G304 -- operator-chosen private input
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
		b, readErr := os.ReadFile(o.labels) // #nosec G304 -- operator-chosen private input
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
	c := newConverter(inv, labels, ps, now)
	if o.bots != "" {
		b, readErr := os.ReadFile(o.bots) // #nosec G304 -- operator-chosen private input
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
	records, err := newStaged(o.out)
	if err != nil {
		return err
	}
	volume, err := newStaged(o.volumeOut)
	if err != nil {
		records.discard()
		return err
	}
	fail := func(err error) error {
		records.discard()
		volume.discard()
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
	manifestFile, err := newStaged(o.manifest)
	if err != nil {
		return fail(err)
	}
	// Record the pseudonyms before publishing: a bundle must never exist
	// without its names in the registry, while a recorded name whose bundle
	// failed only reserves that name's own pseudonym.
	if err = reg.save(); err != nil {
		manifestFile.discard()
		return fail(err)
	}
	if _, err := manifestFile.raw.Write(manifestBytes); err != nil {
		manifestFile.discard()
		return fail(errOutputs)
	}
	if err := publish(records, volume, manifestFile); err != nil {
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
	final string
	file  *os.File
	raw   io.Writer // digest and count, after compression
	gz    *gzip.Writer
	hash  hash.Hash
	bytes *countingWriter
	rows  int64
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

func newStaged(final string) (*staged, error) {
	f, err := os.CreateTemp(filepath.Dir(final), ".domlog-stream-*.tmp")
	if err != nil {
		return nil, errOutputs
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, errOutputs
	}
	h := sha256.New()
	cw := &countingWriter{}
	s := &staged{final: final, file: f, hash: h, bytes: cw}
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

func (s *staged) discard() {
	s.file.Close()
	os.Remove(s.file.Name())
}

// publish links every staged file to its final name, which refuses to
// replace an existing file, and the manifest last. On failure it removes
// what this run published, so no bundle exists without its manifest.
func publish(files ...*staged) error {
	var done []string
	for _, s := range files {
		if err := s.file.Sync(); err != nil {
			break
		}
		if err := s.file.Close(); err != nil {
			break
		}
		if err := os.Link(s.file.Name(), s.final); err != nil {
			break
		}
		done = append(done, s.final)
	}
	for _, s := range files {
		s.discard()
	}
	if len(done) != len(files) {
		for _, p := range done {
			os.Remove(p)
		}
		return errOutputs
	}
	return nil
}

func saltFingerprint(salt []byte) string {
	sum := sha256.Sum256(salt)
	return hex.EncodeToString(sum[:6])
}

func loadOrCreateSalt(path string) ([]byte, error) {
	salt, err := readSalt(path)
	if !errors.Is(err, os.ErrNotExist) {
		return salt, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, errSaltUnsafe
	}
	salt = make([]byte, 32)
	if _, err = rand.Read(salt); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- operator-chosen salt path
	if errors.Is(err, os.ErrExist) {
		return readSalt(path)
	}
	if err != nil {
		return nil, errSaltUnsafe
	}
	_, writeErr := f.Write(salt)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return nil, errSaltUnsafe
	}
	return salt, nil
}

func readSalt(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- operator-chosen salt path; symlinks refused
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

func main() {
	if err := run(os.Args[1:], os.Stdout, env{now: time.Now, revision: readBuildRevision}); err != nil {
		fmt.Fprintln(os.Stderr, "domlog-stream:", err)
		os.Exit(1)
	}
}
