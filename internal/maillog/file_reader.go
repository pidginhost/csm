package maillog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// maxLogLineBytes caps a single mail-log line. Real syslog lines top
// out around 8 KB; 64 KB is generous yet bounded. Without this cap a
// malformed source could ship a multi-gigabyte "line" and turn the
// reader into an OOM vector.
const maxLogLineBytes = 64 * 1024

// FileReader tails a single log file. It uses a 2-second polling loop
// because rsyslog/syslog-ng don't reliably trigger inotify events on
// every line written, and periodic path re-stat checks for log rotation.
//
// On context cancel the reader closes the output channel and returns.
type FileReader struct {
	path string
}

// NewFileReader constructs a FileReader for the given path.
func NewFileReader(path string) *FileReader { return &FileReader{path: path} }

// Run starts the polling loop and returns the line channel. Returns an
// error only when the path can't be opened at all; runtime errors during
// polling are best-effort logged via stderr but do not stop the reader.
func (r *FileReader) Run(ctx context.Context) (<-chan Line, error) {
	f, reader, ino, err := r.open()
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", r.path, err)
	}
	out := make(chan Line, 64)
	go r.loop(ctx, out, f, reader, ino)
	return out, nil
}

// readBoundedLine reads up to and including the next '\n'. If the line
// exceeds maxBytes, the returned data is capped at maxBytes, the reader
// is advanced past the line's terminating newline so framing stays
// intact for the next call, and truncated=true is returned. Callers must
// treat truncated records as untrusted and skip them.
func readBoundedLine(r *bufio.Reader, maxBytes int) (string, bool, error) {
	var b strings.Builder
	truncated := false
	for {
		chunk, err := r.ReadSlice('\n')
		if len(chunk) > 0 {
			switch {
			case truncated:
				// drain remainder to align on next newline
			case b.Len()+len(chunk) <= maxBytes:
				b.Write(chunk)
			default:
				if room := maxBytes - b.Len(); room > 0 {
					b.Write(chunk[:room])
				}
				truncated = true
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return b.String(), truncated, err
	}
}

func (r *FileReader) open() (*os.File, *bufio.Reader, uint64, error) {
	return r.openAt(0, io.SeekEnd)
}

func (r *FileReader) openRotated() (*os.File, *bufio.Reader, uint64, error) {
	return r.openAt(0, io.SeekStart)
}

func (r *FileReader) openAt(offset int64, whence int) (*os.File, *bufio.Reader, uint64, error) {
	f, err := os.Open(r.path) // #nosec G304 -- operator-supplied log path
	if err != nil {
		return nil, nil, 0, err
	}
	if _, seekErr := f.Seek(offset, whence); seekErr != nil {
		_ = f.Close()
		return nil, nil, 0, seekErr
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, 0, err
	}
	return f, bufio.NewReader(f), inode(st), nil
}

func (r *FileReader) loop(ctx context.Context, out chan<- Line, f *os.File, reader *bufio.Reader, lastIno uint64) {
	defer close(out)
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()
	// Rotation safety-net: even if every poll tick finds zero EOFs (a
	// continuously-active log), still re-stat once per minute so a
	// rotation that happens during a sustained write burst is caught
	// without waiting for the next idle period.
	rotate := time.NewTicker(time.Minute)
	defer rotate.Stop()

	reopenOnRotate := func() {
		st, err := os.Stat(r.path)
		if err != nil {
			return
		}
		if inode(st) == lastIno {
			return
		}
		nf, nr, ino, err := r.openRotated()
		if err != nil {
			fmt.Fprintf(os.Stderr, "maillog file_reader %s reopen: %v\n", r.path, err)
			return
		}
		_ = f.Close()
		f = nf
		reader = nr
		lastIno = ino
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			for {
				line, truncated, err := readBoundedLine(reader, maxLogLineBytes)
				if err != nil {
					if truncated {
						fmt.Fprintf(os.Stderr, "maillog file_reader %s: oversized line skipped at %d bytes\n", r.path, maxLogLineBytes)
					}
					// Tight rotation detection: every time the reader
					// hits EOF or any I/O error we re-stat the path so a
					// post-rotate log is picked up by the next poll tick
					// rather than waiting for the safety-net ticker.
					reopenOnRotate()
					break
				}
				if truncated {
					fmt.Fprintf(os.Stderr, "maillog file_reader %s: oversized line skipped at %d bytes\n", r.path, maxLogLineBytes)
					continue
				}
				select {
				case out <- Line{Source: "file", Message: line}:
				case <-ctx.Done():
					return
				}
			}
		case <-rotate.C:
			reopenOnRotate()
		}
	}
}
