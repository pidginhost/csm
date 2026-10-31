package yaraipc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"
)

// DecodeScanReply decodes a scan_fd reply payload. It requires an explicit
// matches array, including for a clean scan, and refuses unknown fields and
// trailing data: an empty or unrelated reply must not stand in for a
// completed scan. A clean scan returns an empty, non-nil slice.
func DecodeScanReply(payload []byte) ([]Match, error) {
	if !utf8.Valid(payload) {
		return nil, errors.New("yaraipc: invalid scan_fd reply")
	}
	var res scanFDResult
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&res); err != nil {
		return nil, fmt.Errorf("yaraipc: decode scan_fd reply: %w", err)
	}
	if res.Matches == nil {
		return nil, errors.New("yaraipc: scan_fd reply has no matches array")
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, errors.New("yaraipc: scan_fd reply has trailing data")
	}
	return res.Matches, nil
}

// ReopenReadOnly opens a second, read-only description of the regular file f,
// so a worker that receives it cannot write the file or move the caller's
// offset, and the caller's flags stay as they were.
func ReopenReadOnly(f *os.File) (*os.File, error) {
	if f == nil {
		return nil, errors.New("yaraipc: no descriptor")
	}
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("descriptor is not a regular file")
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var ro *os.File
	var openErr error
	// Control keeps the source open across the reopen even if the scan's
	// owner closes it after a timeout. Fd neither pins it nor preserves flags.
	if err := rc.Control(func(fd uintptr) {
		// #nosec G304 -- reopens a descriptor this process holds open inside Control.
		ro, openErr = os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", fd), os.O_RDONLY, 0)
	}); err != nil {
		return nil, err
	}
	return ro, openErr
}
