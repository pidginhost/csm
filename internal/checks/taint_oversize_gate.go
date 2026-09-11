package checks

import (
	"io"
	"os"

	"github.com/pidginhost/csm/internal/jstaint"
	"github.com/pidginhost/csm/internal/phptaint"
)

// jsTaintOversizePeekBytes bounds the prefix read that decides whether an
// oversize file could be JavaScript. It matches the PHP peek so both gates
// judge the same window of the same file.
const jsTaintOversizePeekBytes = 64 << 10

// taintSourcePrefixLooks reads a bounded prefix of a file too large to analyze
// and asks pred whether the content could be source of that language.
//
// Every failure answers yes. An unreadable file, a file swapped under us, a
// FIFO that would block: each is a file this scan could not examine, which is
// exactly what the coverage report exists to name. The failure direction that
// matters is the other one -- silently deciding a file was uninteresting and
// dropping it from the report.
func taintSourcePrefixLooks(path string, expected os.FileInfo, limit int64, pred func([]byte) bool) bool {
	if reader, ok := osFS.(phpRegularFilePrefixReader); ok {
		prefix, err := reader.ReadRegularFilePrefix(path, expected, limit)
		if err != nil {
			return true
		}
		return pred(prefix)
	}

	f, err := osFS.Open(path)
	if err != nil {
		return true
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !sameFileSnapshot(expected, opened) {
		return true
	}
	prefix, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return true
	}
	after, err := f.Stat()
	if err != nil || !sameFileSnapshot(opened, after) {
		return true
	}
	return pred(prefix)
}

// jsFileMayBeJS reports whether a file too large to analyze nonetheless looks
// like JavaScript source, judged only by its leading bytes.
func jsFileMayBeJS(path string, expected os.FileInfo) bool {
	return taintSourcePrefixLooks(path, expected, jsTaintOversizePeekBytes, jstaint.MayBeJSSource)
}

// phpFileMayBePHP reports whether a file too large to analyze nonetheless
// looks like PHP source, judged only by its leading bytes.
func phpFileMayBePHP(path string, expected os.FileInfo) bool {
	return taintSourcePrefixLooks(path, expected, phpTaintOversizePeekBytes, phptaint.MayBePHPSource)
}
