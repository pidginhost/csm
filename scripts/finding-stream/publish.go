package main

import (
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// stagedFile is a private temporary file in its destination's directory.
type stagedFile interface {
	io.Writer
	Sync() error
	Close() error
	Name() string
}

// fileOps is every filesystem step publication takes, so a test can fail
// each one.
type fileOps struct {
	createTemp func(dir, pattern string) (stagedFile, error)
	link       func(oldname, newname string) error
	rename     func(oldpath, newpath string) error
	remove     func(name string) error
}

func osFileOps() fileOps {
	return fileOps{
		createTemp: func(dir, pattern string) (stagedFile, error) { return os.CreateTemp(dir, pattern) },
		link:       os.Link,
		rename:     os.Rename,
		remove:     os.Remove,
	}
}

const (
	stagePattern = ".finding-stream-*"
	backupPrefix = ".finding-stream-backup-"
)

// stagedOutput is a complete output waiting to replace its destination.
// digest covers the staged bytes, which are the bytes that get published.
type stagedOutput struct {
	temp, dest, digest string
}

// stageOutput writes one output next to its destination. The file is created
// owner-only and synced before it can be published; on any failure it is
// removed and nothing else is touched.
func stageOutput(ops fileOps, path string, encode func(io.Writer) error) (stagedOutput, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return stagedOutput{}, errPublish
	}
	f, err := ops.createTemp(dir, stagePattern)
	if err != nil {
		return stagedOutput{}, errPublish
	}
	h := sha256.New()
	err = encode(io.MultiWriter(f, h))
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		if removeErr := removeTemporary(ops, f.Name()); removeErr != nil {
			return stagedOutput{}, errCleanup
		}
		return stagedOutput{}, errPublish
	}
	return stagedOutput{temp: f.Name(), dest: path, digest: hex.EncodeToString(h.Sum(nil))}, nil
}

func removeTemporary(ops fileOps, path string) error {
	err := ops.remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func discardStaged(ops fileOps, staged []stagedOutput) error {
	var err error
	for _, s := range staged {
		err = errors.Join(err, removeTemporary(ops, s.temp))
	}
	return err
}

// encodeRows writes gzip JSONL. Encoding, flush and gzip finalization errors
// all reach the caller: a stream missing its gzip trailer is not complete.
func encodeRows[T any](dst io.Writer, rows []T) (err error) {
	zw := gzip.NewWriter(dst)
	w := bufio.NewWriter(zw)
	defer func() { err = errors.Join(err, w.Flush(), zw.Close()) }()
	enc := json.NewEncoder(w)
	for i := range rows {
		if err := enc.Encode(&rows[i]); err != nil {
			return err
		}
	}
	return nil
}

// publishOutputs replaces each destination in order; callers put the manifest
// last, so a bundle is complete only once its manifest is. An existing
// destination is first hard-linked to a backup, so a later failure can put
// every earlier destination back. When that restore itself fails the backups
// stay where they are and the error says so; it never claims the previous
// bundle is intact.
func publishOutputs(ops fileOps, staged []stagedOutput) error {
	type published struct{ dest, backup string }
	var done []published
	rollback := func(cleanupErr error) error {
		failed := false
		for i := len(done) - 1; i >= 0; i-- {
			p := done[i]
			var err error
			if p.backup != "" {
				err = ops.rename(p.backup, p.dest)
			} else {
				err = ops.remove(p.dest)
			}
			failed = failed || err != nil
		}
		if failed {
			return errRollback
		}
		if cleanupErr != nil {
			return errCleanup
		}
		return errPublish
	}
	for i, s := range staged {
		backup := ""
		if _, err := os.Lstat(s.dest); err == nil {
			backup = filepath.Join(filepath.Dir(s.dest), backupPrefix+rand.Text())
			if linkErr := ops.link(s.dest, backup); linkErr != nil {
				return rollback(discardStaged(ops, staged[i:]))
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return rollback(discardStaged(ops, staged[i:]))
		}
		if err := ops.rename(s.temp, s.dest); err != nil {
			var cleanupErr error
			if backup != "" {
				cleanupErr = removeTemporary(ops, backup)
			}
			return rollback(errors.Join(cleanupErr, discardStaged(ops, staged[i:])))
		}
		done = append(done, published{s.dest, backup})
	}
	var cleanupErr error
	for _, p := range done {
		if p.backup != "" {
			cleanupErr = errors.Join(cleanupErr, removeTemporary(ops, p.backup))
		}
	}
	if cleanupErr != nil {
		// Every destination, including the manifest, is already committed.
		// Earlier backups may be gone, so claiming or attempting rollback
		// here would misrepresent the state of the bundle.
		return errPublishedCleanup
	}
	return nil
}
