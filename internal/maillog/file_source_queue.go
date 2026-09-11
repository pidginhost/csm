package maillog

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type mailLogFile interface {
	io.Reader
	io.Seeker
	Stat() (os.FileInfo, error)
	Close() error
}

type mailFileInput struct {
	file         mailLogFile
	reader       *bufio.Reader
	ino          uint64
	offset, size int64
}

// One identity per open or rewind prevents a late Stat from joining bytes from
// different file generations. All mutable generation fields use the owner lock.
type fileSourceGeneration struct {
	file               mailLogFile
	read, settled, end int64
	physical           int64
	revision           uint64
	eof, selected      bool
	known, invalid     bool
	lagAt              time.Time
}

type fileSourceQueue struct {
	mu                      sync.Mutex
	seen                    bool
	failures                fileSourceFault
	sampleFailed, uncertain bool
	current                 *fileSourceGeneration
	readerAt, sampleAt      time.Time
}

type fileSourceFault uint8

const (
	fileReadFault fileSourceFault = 1 << iota
	fileCursorFault
	fileOpenFault
	fileCloseFault
	fileExitFault
)

func (s *fileSourceQueue) attach(input *mailFileInput, known bool) *fileSourceGeneration {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := &fileSourceGeneration{file: input.file, read: input.offset, settled: input.offset, physical: input.offset, end: input.size, known: known}
	g.invalid = input.size < input.offset
	s.current, s.seen = g, true
	s.failures, s.sampleFailed = 0, false
	s.readerAt = time.Now()
	g.refreshLag(s.readerAt, false)
	return g
}

func (g *fileSourceGeneration) refreshLag(now time.Time, progress bool) {
	if g.end <= g.settled || g.eof && g.end <= g.read {
		g.lagAt = time.Time{}
	} else if progress || g.lagAt.IsZero() {
		g.lagAt = now
	}
}

func (s *fileSourceQueue) operation() {
	s.mu.Lock()
	s.readerAt = time.Now()
	s.mu.Unlock()
}

func (s *fileSourceQueue) idle() {
	s.mu.Lock()
	s.readerAt = time.Time{}
	s.mu.Unlock()
}

func (s *fileSourceQueue) outcome(fault fileSourceFault, failed bool) {
	s.mu.Lock()
	if failed {
		s.failures |= fault
		s.uncertain = true
	} else {
		s.failures &^= fault
	}
	s.mu.Unlock()
}

func (s *fileSourceQueue) consume(g *fileSourceGeneration, n, buffered int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	g.read += int64(n)
	g.physical = g.read + int64(buffered)
	g.end = max(g.end, g.physical)
	g.revision++
	g.eof, g.selected = errors.Is(err, io.EOF), err == nil
	if g.eof && !g.invalid {
		g.end, g.known = g.read, true
	}
	if n > 0 {
		s.readerAt = now
	}
	g.refreshLag(now, n > 0)
}

func (s *fileSourceQueue) complete(g *fileSourceGeneration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g.settled, g.selected = g.read, false
	g.revision++
	s.readerAt = time.Now()
	g.refreshLag(s.readerAt, true)
}

func (q *Queue) discardFile(g *fileSourceGeneration, bufferedRecords int) {
	s := &q.file
	s.mu.Lock()
	defer s.mu.Unlock()
	if g.selected {
		bufferedRecords++
	}
	if bufferedRecords > 0 {
		q.health.Lose(time.Now(), uint64(bufferedRecords))
	}
	s.current = nil
	// Disk bytes do not establish record boundaries, and writers can append
	// until close. Retain uncertainty without manufacturing a record count.
	s.uncertain = true
}

func (s *fileSourceQueue) finish() {
	s.mu.Lock()
	s.readerAt = time.Time{}
	s.mu.Unlock()
}

func (s *fileSourceQueue) replaced() {
	s.mu.Lock()
	s.failures, s.sampleFailed = 0, false
	s.mu.Unlock()
}

func bufferedMailRecords(reader *bufio.Reader) int {
	// Peek only bytes already in memory; this must not read a closing source.
	data, _ := reader.Peek(reader.Buffered())
	return bytes.Count(data, []byte{'\n'})
}

func (s *fileSourceQueue) sample() {
	s.mu.Lock()
	g := s.current
	if g == nil {
		s.mu.Unlock()
		return
	}
	revision := g.revision
	s.sampleAt = time.Now()
	s.mu.Unlock()
	info, err := g.file.Stat()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sampleAt = time.Time{}
	if s.current != g {
		return
	}
	s.sampleFailed = err != nil
	s.uncertain = s.uncertain || err != nil
	if err != nil || g.revision != revision {
		return
	}
	if info.Size() < g.physical {
		g.invalid, s.uncertain = true, true
	} else if !g.invalid {
		g.end, g.known = info.Size(), true
	}
	g.refreshLag(time.Now(), false)
}

func (s *fileSourceQueue) sampleLoop(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			s.sample()
		}
	}
}

func (s *fileSourceQueue) snapshot(now time.Time) (queuehealth.Status, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := queuehealth.Status{Status: "ok", DepthUnit: "bytes", CapacityUnavailable: true, DroppedLowerBound: s.uncertain, LagBasis: "consumer_progress"}
	if g := s.current; g != nil {
		row.DepthUnavailable = !g.known || g.invalid || s.sampleFailed
		if !row.DepthUnavailable {
			row.Depth = int(max(0, g.end-g.settled))
		}
		if !g.lagAt.IsZero() {
			row.LagSeconds = max(0, now.Sub(g.lagAt).Seconds())
		}
	} else {
		// No descriptor left to measure. Zero bytes would be an invented
		// reading of a source that is no longer open.
		row.DepthUnavailable = true
	}
	for _, at := range []time.Time{s.readerAt, s.sampleAt} {
		if !at.IsZero() {
			row.ProcessingSeconds = max(row.ProcessingSeconds, now.Sub(at).Seconds())
		}
	}
	switch {
	case s.failures != 0 || s.sampleFailed:
		row.Status, row.Reason = "degraded", "source_io"
	case row.ProcessingSeconds >= time.Minute.Seconds():
		row.Status, row.Reason = "degraded", "processing_lag"
	case row.LagSeconds >= time.Minute.Seconds():
		row.Status, row.Reason = "degraded", "consumer_stalled"
	}
	return row, s.seen
}
