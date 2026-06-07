package intel

import (
	"io"
	"os"
	"strings"
)

// eximMainLog is the cPanel/exim delivery log. Deferrals to remote providers
// are recorded here; CSM only reads it.
const eximMainLog = "/var/log/exim_mainlog"

// Default read bounds: enough recent history to see a throttle pattern without
// reading an unbounded multi-gigabyte log.
const (
	defaultTailBytes = 8 << 20 // 8 MiB
	defaultTailLines = 20000
)

// Reporter produces a deferral Report for the host.
type Reporter interface {
	Report() (Report, error)
}

// EmptyReporter yields an empty report. It stands in on platforms with no exim
// log (non-cPanel) until their adapters land.
type EmptyReporter struct{}

func (EmptyReporter) Report() (Report, error) { return emptyReport(), nil }

// EximSource reads the tail of exim_mainlog and builds a deferral report.
type EximSource struct {
	path      string
	tailBytes int64
	tailLines int
	readTail  func(path string, maxBytes int64, maxLines int) []string
}

// NewEximSource returns a source reading the standard exim_mainlog location.
func NewEximSource() *EximSource {
	return &EximSource{
		path:      eximMainLog,
		tailBytes: defaultTailBytes,
		tailLines: defaultTailLines,
		readTail:  tailLines,
	}
}

// Report reads the recent tail of the log and aggregates deferrals. A missing
// or unreadable log yields an empty report, not an error: no log just means no
// observed deferrals, and this is a read-only visibility surface.
func (s *EximSource) Report() (Report, error) {
	return BuildReport(s.readTail(s.path, s.tailBytes, s.tailLines)), nil
}

// tailLines returns up to maxLines trailing lines of the file, reading at most
// the last maxBytes so a huge log never loads whole into memory. A partial
// first line (from the byte-window cut) is dropped.
func tailLines(path string, maxBytes int64, maxLines int) []string {
	if maxBytes <= 0 || maxLines <= 0 {
		return nil
	}
	f, err := os.Open(path) // #nosec G304 -- fixed exim_mainlog path, operator-scoped.
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil
	}

	var data []byte
	if info.Size() > maxBytes {
		if _, err := f.Seek(-maxBytes, io.SeekEnd); err != nil {
			return nil
		}
		data, _ = io.ReadAll(f)
		// Drop the first (likely partial) line after a mid-file seek.
		if nl := strings.IndexByte(string(data), '\n'); nl >= 0 {
			data = data[nl+1:]
		}
	} else {
		data, _ = io.ReadAll(f)
	}

	text := strings.TrimSuffix(string(data), "\n")
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines
}
