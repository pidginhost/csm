//go:build linux

package daemon

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/sys/unix"
)

// hashEventFD returns the SHA-256 of exactly expectedSize bytes behind an
// event descriptor. prefix must be the bytes the scanner already read at
// offset zero. Reusing them prevents an in-place overwrite from making the CMS
// decision cover different leading bytes than signature and YARA scanning.
// The fixed expected size bounds the work and prevents a concurrently growing
// file from keeping an analyzer busy indefinitely. An empty result means the
// file could not be read consistently.
func hashEventFD(fd int, prefix []byte, expectedSize int64) string {
	if expectedSize < int64(len(prefix)) || expectedSize < 0 {
		return ""
	}
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Size != expectedSize {
		return ""
	}

	h := sha256.New()
	_, _ = h.Write(prefix)
	buf := make([]byte, 64*1024)
	offset := int64(len(prefix))
	for offset < expectedSize {
		want := int64(len(buf))
		if remaining := expectedSize - offset; remaining < want {
			want = remaining
		}
		n, err := unix.Pread(fd, buf[:int(want)], offset)
		if n > 0 {
			_, _ = h.Write(buf[:n])
			offset += int64(n)
		}
		if err != nil {
			if err == unix.EINTR && n == 0 {
				continue
			}
			return ""
		}
		if n == 0 {
			return ""
		}
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || after.Size != expectedSize {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
