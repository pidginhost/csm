package maillog

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"time"
)

// FileReader tails a single log file. It uses a 2-second polling loop
// because rsyslog/syslog-ng don't reliably trigger inotify events on
// every line written, and a 5-minute rotation reopen for log rotation.
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

func (r *FileReader) open() (*os.File, *bufio.Reader, uint64, error) {
	f, err := os.Open(r.path) // #nosec G304 -- operator-supplied log path
	if err != nil {
		return nil, nil, 0, err
	}
	if _, seekErr := f.Seek(0, io.SeekEnd); seekErr != nil {
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
	rotate := time.NewTicker(5 * time.Minute)
	defer rotate.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				select {
				case out <- Line{Source: "file", Message: line}:
				case <-ctx.Done():
					return
				}
			}
		case <-rotate.C:
			if st, err := os.Stat(r.path); err == nil {
				if inode(st) != lastIno {
					nf, nr, ino, err := r.open()
					if err != nil {
						fmt.Fprintf(os.Stderr, "maillog file_reader %s reopen: %v\n", r.path, err)
						continue
					}
					_ = f.Close()
					f = nf
					reader = nr
					lastIno = ino
				}
			}
		}
	}
}
