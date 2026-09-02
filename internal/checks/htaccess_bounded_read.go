package checks

import (
	"io"
)

// htaccessMaxFileBytes bounds every scheduled .htaccess read. A real
// .htaccess is a few kilobytes; the ceiling matches the per-line limit the
// directive scanner already enforces. Reading the whole file with no bound
// let a tenant park a multi-gigabyte .htaccess and turn the deep scan into
// an out-of-memory crash loop.
const htaccessMaxFileBytes = htaccessMaxLineBytes

// readHtaccessBounded returns the file's content when it is at most
// htaccessMaxFileBytes. An oversized file yields ok=false with no error: the
// caller knows the file exists but cannot be judged, which differs from a
// missing file. Any other failure is returned as err.
func readHtaccessBounded(path string) (data []byte, ok bool, err error) {
	f, err := osFS.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() || info.Size() > htaccessMaxFileBytes {
		return nil, false, nil
	}
	// Read one byte past the limit: a file that grows between Stat and
	// Read must not slip through as complete.
	data, err = io.ReadAll(io.LimitReader(f, htaccessMaxFileBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > htaccessMaxFileBytes {
		return nil, false, nil
	}
	return data, true, nil
}

// htaccessOversized reports whether err/ok from readHtaccessBounded mean
// "present but too large".
func htaccessOversized(ok bool, err error) bool {
	return !ok && err == nil
}
