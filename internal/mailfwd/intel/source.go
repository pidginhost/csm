package intel

import (
	"bytes"
	"fmt"
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
// the last maxBytes so a huge log never loads whole into memory.
func tailLines(path string, maxBytes int64, maxLines int) []string {
	if maxBytes <= 0 || maxLines <= 0 {
		return nil
	}
	f, err := os.Open(path) // #nosec G304 -- fixed exim_mainlog path, operator-scoped.
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	lines, err := readFileTail(f, maxBytes)
	if err != nil {
		return nil
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines
}

// readFileTail reads at most the last maxBytes of a regular file, seeking past
// the rest, and splits them into lines. A partial first line (from the
// byte-window cut) is dropped.
func readFileTail(f *os.File, maxBytes int64) ([]string, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", f.Name())
	}

	offset := info.Size() - maxBytes
	if offset > 0 {
		if _, seekErr := f.Seek(offset, io.SeekStart); seekErr != nil {
			return nil, seekErr
		}
	}
	// The limit holds the bound even if the file grew after Stat.
	data, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return nil, err
	}
	if offset > 0 {
		if nl := bytes.IndexByte(data, '\n'); nl >= 0 {
			data = data[nl+1:]
		}
	}

	text := strings.TrimSuffix(string(data), "\n")
	if text == "" {
		return nil, nil
	}
	return strings.Split(text, "\n"), nil
}
