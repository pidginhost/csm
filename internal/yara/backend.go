package yara

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"github.com/pidginhost/csm/internal/contenttype"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// Backend is the consumable scanning surface shared by the in-process
// *Scanner and out-of-process process supervisor. Callers should depend
// on this interface (via Active()) so they keep working when the daemon
// switches backends at startup. String-valued rule metadata travels on
// Match.Meta, so adapters that historically reached for the compiled
// *yara_x.Rules object (e.g. emailav) now work uniformly under both
// backends -- see internal/emailav/yarax.go.
type Backend interface {
	ScanFile(path string, maxBytes int) []Match
	ScanBytes(data []byte) []Match
	RuleCount() int
	Reload() error
}

// CheckedScanner is an optional capability on a Backend. ScanBytesChecked
// reports a scan failure (worker down, payload too large for the IPC frame, a
// transport error) distinctly from "no matches". Plain ScanBytes cannot: it
// returns nil for both a clean file and a failed scan, so a caller with a
// fail-closed policy -- email AV, finding re-check -- would auto-clear a file
// it never actually scanned. Both production backends implement it; the
// in-process stub returns a nil error because it cannot fail this way.
type CheckedScanner interface {
	ScanBytesChecked(data []byte) ([]Match, error)
}

// FileScanResult binds path-scan matches to the exact bytes the backend
// scanned. ContentSHA256 is lowercase hex so it can be copied directly into a
// finding and transported over the worker IPC boundary.
type FileScanResult struct {
	Matches       []Match
	ContentSHA256 string
}

// CheckedFileScanner is the path-based equivalent of CheckedScanner. It is
// used when a payload is too large for inline worker IPC and the worker must
// reopen the file without turning a worker or read failure into a clean scan.
type CheckedFileScanner interface {
	ScanFileChecked(path string, maxBytes int) (FileScanResult, error)
}

// CheckedFDScanner scans an open file the backend reads itself, such as a
// mail part memfd passed to the YARA worker.
type CheckedFDScanner interface {
	ScanFDChecked(f *os.File, size int64) ([]Match, error)
}

// ScanFileDescriptorChecked scans the first size bytes of f, failing closed:
// a backend that cannot take the descriptor returns an error, never a clean
// result. A backend without the capability (in-process YARA) gets the bytes.
// No name goes with them, so the archive-by-name skip does not apply.
func ScanFileDescriptorChecked(b Backend, f *os.File, size int64) ([]Match, error) {
	if size <= 0 {
		return nil, fmt.Errorf("yara: invalid part size: %d", size)
	}
	if b == nil {
		return nil, errors.New("yara: backend unavailable")
	}
	if fs, ok := b.(CheckedFDScanner); ok {
		return fs.ScanFDChecked(f, size)
	}
	data, err := io.ReadAll(io.NewSectionReader(f, 0, size))
	if err != nil {
		return nil, fmt.Errorf("yara: read part: %w", err)
	}
	if int64(len(data)) != size {
		return nil, fmt.Errorf("yara: read part: got %d of %d bytes: %w", len(data), size, io.ErrUnexpectedEOF)
	}
	return ScanBytesChecked(b, "", data)
}

// ScanBytesChecked scans data, read from the file called name, via b,
// surfacing a scan error when b supports the CheckedScanner capability.
// Backends without it fall back to the error-free ScanBytes. Callers that must
// fail closed on an unscannable payload should use this instead of
// Backend.ScanBytes.
//
// The archive policy lives here, at the backend-agnostic boundary, because it
// needs the name: raw archive bytes are not scannable and their stored entries
// trip rules with spurious tokens, so a file that is an archive by name and by
// magic is left to the extraction-time scan. Magic alone is not enough -- PHP
// executes past any leading bytes -- so an executable name is always scanned.
func ScanBytesChecked(b Backend, name string, data []byte) ([]Match, error) {
	if b == nil {
		return nil, errors.New("yara: backend unavailable")
	}
	if contenttype.IsArchiveFile(name, data) {
		return nil, nil
	}
	if cs, ok := b.(CheckedScanner); ok {
		return cs.ScanBytesChecked(data)
	}
	return b.ScanBytes(data), nil
}

// ScanFileChecked scans a path via b. Backends without the checked capability
// return an error because a caller cannot safely distinguish failure from a
// clean result through Backend.ScanFile.
func ScanFileChecked(b Backend, path string, maxBytes int) (FileScanResult, error) {
	if b == nil {
		return FileScanResult{}, errors.New("yara: backend unavailable")
	}
	if cs, ok := b.(CheckedFileScanner); ok {
		result, err := cs.ScanFileChecked(path, maxBytes)
		if err != nil {
			return FileScanResult{}, err
		}
		if len(result.ContentSHA256) != 64 {
			return FileScanResult{}, errors.New("yara: checked file scan returned an invalid content hash")
		}
		if _, err := hex.DecodeString(result.ContentSHA256); err != nil {
			return FileScanResult{}, fmt.Errorf("yara: checked file scan returned an invalid content hash: %w", err)
		}
		return result, nil
	}
	return FileScanResult{}, errors.New("yara: backend does not support checked file scans")
}

var activeBackend atomic.Pointer[backendHolder]

var cacheGeneration atomic.Uint64

// CacheGeneration changes when rules or the active backend change. Rule
// counts alone cannot invalidate verdicts after an edit to an existing rule.
func CacheGeneration() uint64 { return cacheGeneration.Load() }

// InvalidateCaches retires verdicts after loading rules, including a worker
// restart that may load different on-disk content without an explicit reload.
func InvalidateCaches() { cacheGeneration.Add(1) }

type backendHolder struct{ b Backend }

// Active returns the configured scanning backend. When SetActive has
// not been called, it falls back to the in-process singleton Global().
// Returns a nil interface if neither is available (e.g. a !yara build
// with no supervisor wired up); callers must nil-check.
func Active() Backend {
	if h := activeBackend.Load(); h != nil && h.b != nil {
		return h.b
	}
	if g := Global(); g != nil {
		return g
	}
	return nil
}

// SetActive installs a scanning backend. Calling with nil clears the
// override and restores the Global() fallback. Safe to call at any
// time; reads in-flight see the prior backend finish and the next read
// sees the new one.
func SetActive(b Backend) {
	defer InvalidateCaches()
	if b == nil {
		activeBackend.Store(nil)
		return
	}
	activeBackend.Store(&backendHolder{b: b})
}

// ScanContentOrPathChecked scans data inline and, when the payload cannot fit
// one IPC frame, retries by asking the backend to read path itself. The frame
// ceiling is a property of the transport, not of the file, so reporting it as a
// scan failure leaves a file unscanned that the worker could have read directly
// -- and lets an attacker put a payload out of reach by padding it past the
// inline ceiling.
//
// The returned digest is the SHA-256 of the bytes the backend actually scanned,
// and is empty when the inline scan succeeded: the caller already holds the
// digest of the snapshot it passed in. Only the oversize case retries; any
// other scan error surfaces unchanged so fail-closed callers stay fail-closed.
func ScanContentOrPathChecked(b Backend, path string, data []byte, maxBytes int) ([]Match, string, error) {
	matches, err := ScanBytesChecked(b, path, data)
	if !errors.Is(err, yaraipc.ErrPayloadTooLarge) {
		return matches, "", err
	}
	res, pathErr := ScanFileChecked(b, path, maxBytes)
	if pathErr != nil {
		return nil, "", pathErr
	}
	return res.Matches, res.ContentSHA256, nil
}
