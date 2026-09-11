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

// defaultGoneGrace is how long the source path must stay missing before
// the reader declares the source gone. Long enough to ride out a
// logrotate create-delay (rename old -> create new), short enough that an
// operator notices a real syslog->journald migration quickly.
const defaultGoneGrace = 90 * time.Second

// FileReader tails a single log file. It uses a 2-second polling loop
// because rsyslog/syslog-ng don't reliably trigger inotify events on
// every line written, and periodic path re-stat checks for log rotation.
//
// On context cancel the reader closes the output channel and returns.
type FileReader struct {
	path  string
	queue *Queue

	// onGone, when set, fires once when the source path has been missing
	// continuously for goneGrace. A FileReader whose path vanishes mid-run
	// (e.g. a syslog->journald migration) otherwise tails a dead fd
	// silently; the callback lets the daemon surface a finding and mark the
	// watcher unhealthy. onRestored fires after the path returns and the
	// reader can use it again.
	onGone     func(error)
	onRestored func()
	goneGrace  time.Duration
	nowFn      func() time.Time

	// gone-tracking state, touched only by the single loop goroutine.
	firstMissing time.Time
	goneFired    bool
	restoreReady bool
}

// NewFileReader constructs a FileReader for the given path.
func NewFileReader(path string, queue *Queue) *FileReader {
	return &FileReader{path: path, queue: queue, goneGrace: defaultGoneGrace, nowFn: time.Now}
}

// SetOnGone installs a callback invoked once when the source path has been
// missing for longer than the grace period. Must be called before Run.
func (r *FileReader) SetOnGone(fn func(error)) { r.onGone = fn }

// SetOnRestored installs a callback invoked once after a previously-gone
// source path returns and the reader is using it again. Must be called
// before Run.
func (r *FileReader) SetOnRestored(fn func()) { r.onRestored = fn }

// recordStat advances the missing-source state machine from one stat result.
// It fires onGone once after the path is missing past the grace period and
// arms the restore callback when the path returns.
func (r *FileReader) recordStat(missing bool, missErr error) {
	if !missing {
		if !r.firstMissing.IsZero() && r.goneFired {
			r.restoreReady = true
		}
		r.firstMissing = time.Time{}
		return
	}
	now := r.nowFn()
	if r.firstMissing.IsZero() {
		r.firstMissing = now
	}
	if !r.goneFired && !r.restoreReady && now.Sub(r.firstMissing) >= r.goneGrace {
		r.goneFired = true
		if r.onGone != nil {
			r.onGone(missErr)
		}
	}
}

func (r *FileReader) recordRestored() {
	if !r.restoreReady {
		return
	}
	r.restoreReady = false
	r.goneFired = false
	if r.onRestored != nil {
		r.onRestored()
	}
}

// Run starts the polling loop and returns the line channel. Returns an
// error only when the path can't be opened at all; runtime errors during
// polling are best-effort logged via stderr but do not stop the reader.
func (r *FileReader) Run(ctx context.Context) (<-chan Line, error) {
	input, err := r.open()
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", r.path, err)
	}
	// A usable replacement retires the old source's current failure while
	// retaining its historical uncertainty and delivery loss evidence.
	r.queue.journal.outcome(false, false)
	out := r.queue.channel()
	go r.loop(ctx, out, input)
	return out, nil
}

// Temporary EOF does not finish a log record. Both its bounded prefix and
// discard state must survive until the newline or a change of file generation.
type pendingLogLine struct {
	data      strings.Builder
	truncated bool
	onRead    func(int, int, error)
}

func (p *pendingLogLine) reset() {
	p.data.Reset()
	p.truncated = false
}

func (p *pendingLogLine) read(ctx context.Context, r *bufio.Reader, maxBytes int) (string, bool, error) {
	for {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		chunk, err := r.ReadSlice('\n')
		if p.onRead != nil {
			p.onRead(len(chunk), r.Buffered(), err)
		}
		if len(chunk) > 0 {
			switch {
			case p.truncated:
				// drain remainder to align on next newline
			case p.data.Len()+len(chunk) <= maxBytes:
				p.data.Write(chunk)
			default:
				if room := maxBytes - p.data.Len(); room > 0 {
					p.data.Write(chunk[:room])
				}
				p.truncated = true
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return "", false, err
		}
		line, truncated := p.data.String(), p.truncated
		p.reset()
		return line, truncated, nil
	}
}

func (r *FileReader) open() (*mailFileInput, error) {
	return r.openAt(0, io.SeekEnd)
}

func (r *FileReader) openRotated() (*mailFileInput, error) {
	return r.openAt(0, io.SeekStart)
}

func (r *FileReader) openAt(offset int64, whence int) (*mailFileInput, error) {
	f, err := os.Open(r.path) // #nosec G304 -- operator-supplied log path
	if err != nil {
		return nil, err
	}
	position, seekErr := f.Seek(offset, whence)
	if seekErr != nil {
		_ = f.Close()
		return nil, seekErr
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &mailFileInput{file: f, reader: bufio.NewReader(f), ino: inode(st), offset: position, size: st.Size()}, nil
}

func (r *FileReader) loop(ctx context.Context, out chan<- Line, input *mailFileInput) {
	defer close(out)
	f, reader, lastIno := input.file, input.reader, input.ino
	source := r.queue.file.attach(input, true)
	sampleCtx, stopSample := context.WithCancel(ctx)
	sampleDone := make(chan struct{})
	go r.queue.file.sampleLoop(sampleCtx, sampleDone)
	normal := false
	defer func() {
		defer r.queue.file.finish()
		defer func() { r.queue.discardFile(source, bufferedMailRecords(reader)) }()
		stopSample()
		if !normal {
			r.queue.file.outcome(fileExitFault, true)
		}
		r.queue.file.operation()
		// The sampler still owns its descriptor until the last Stat returns.
		// Closing first can turn normal shutdown into a false source failure.
		<-sampleDone
		closed := false
		defer func() {
			if !closed {
				r.queue.file.outcome(fileExitFault, true)
			}
		}()
		if err := f.Close(); err != nil {
			r.queue.file.outcome(fileCloseFault, true)
		}
		closed = true
	}()

	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()
	// Rotation safety-net: even if every poll tick finds zero EOFs (a
	// continuously-active log), still re-stat once per minute so a
	// rotation that happens during a sustained write burst is caught
	// without waiting for the next idle period.
	rotate := time.NewTicker(time.Minute)
	defer rotate.Stop()
	pending := pendingLogLine{onRead: func(n, buffered int, err error) { r.queue.file.consume(source, n, buffered, err) }}

	rewindOnTruncate := func() {
		buffered := bufferedMailRecords(reader)
		reset, err := rewindTruncatedFile(f, reader)
		r.queue.file.outcome(fileCursorFault, err != nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "maillog file_reader %s rewind: %v\n", r.path, err)
		} else if reset {
			r.queue.discardFile(source, buffered)
			source = r.queue.file.attach(&mailFileInput{file: f}, false)
			pending.reset()
		}
	}

	reopenOnRotate := func() {
		st, err := os.Stat(r.path)
		if err != nil {
			// Track persistent disappearance so a source that vanishes
			// mid-run (syslog->journald migration) surfaces instead of
			// tailing a dead fd in silence.
			r.recordStat(os.IsNotExist(err), err)
			return
		}
		r.recordStat(false, nil)
		if inode(st) == lastIno {
			r.queue.file.outcome(fileOpenFault, false)
			rewindOnTruncate()
			r.recordRestored()
			return
		}
		next, err := r.openRotated()
		if err != nil {
			r.queue.file.outcome(fileOpenFault, true)
			fmt.Fprintf(os.Stderr, "maillog file_reader %s reopen: %v\n", r.path, err)
			return
		}
		_ = f.Close()
		r.queue.discardFile(source, bufferedMailRecords(reader))
		f, reader, lastIno = next.file, next.reader, next.ino
		source = r.queue.file.attach(next, true)
		pending.reset()
		r.recordRestored()
	}

	for {
		select {
		case <-ctx.Done():
			normal = true
			return
		case <-poll.C:
			r.queue.file.operation()
			rewindOnTruncate()
			for {
				line, truncated, err := pending.read(ctx, reader, maxLogLineBytes)
				if err != nil {
					if ctx.Err() != nil {
						normal = true
						return
					}
					r.queue.file.outcome(fileReadFault, !errors.Is(err, io.EOF))
					// Tight rotation detection: every time the reader
					// hits EOF or any I/O error we re-stat the path so a
					// post-rotate log is picked up by the next poll tick
					// rather than waiting for the safety-net ticker.
					reopenOnRotate()
					break
				}
				r.queue.file.outcome(fileReadFault, false)
				if truncated {
					r.queue.lose()
					r.queue.file.complete(source)
					fmt.Fprintf(os.Stderr, "maillog file_reader %s: oversized line skipped at %d bytes\n", r.path, maxLogLineBytes)
					continue
				}
				if !r.queue.sendFile(ctx, out, Line{Source: "file", Message: line}, source) {
					normal = true
					return
				}
			}
			r.queue.file.idle()
		case <-rotate.C:
			r.queue.file.operation()
			reopenOnRotate()
			r.queue.file.idle()
		}
	}
}

func rewindTruncatedFile(f mailLogFile, reader *bufio.Reader) (bool, error) {
	st, err := f.Stat()
	if err != nil {
		return false, err
	}
	offset, err := f.Seek(0, io.SeekCurrent)
	if err != nil || st.Size() >= offset {
		return false, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	// Read-ahead bytes belong to the generation that was truncated. Compare
	// against the descriptor position so those bytes cannot conceal shrinkage.
	reader.Reset(f)
	return true, nil
}
