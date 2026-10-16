package hostfacts

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/antispam"
)

// maxKeyBytes bounds the key file read: a 26-character key, a newline and
// some slack for white space.
const maxKeyBytes = 128

// ReadDQSKey reads the Spamhaus DQS key file without following a final
// symlink or blocking on a FIFO. Surrounding white space is trimmed.
func ReadDQSKey(p string) antispam.KeyFacts {
	k := antispam.KeyFacts{Path: p, UID: -1}
	// #nosec G304 -- the operator's configured key path, opened read-only without following a final link.
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		k.Missing = true
		return k
	}
	if err != nil {
		k.Err = err
		return k
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		k.Err = err
		return k
	}
	if !info.Mode().IsRegular() {
		k.Err = errors.New("not a regular file")
		return k
	}
	k.Mode = info.Mode()
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		k.UID = int(st.Uid)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyBytes+1))
	switch {
	case err != nil:
		k.Err = err
	case len(data) > maxKeyBytes:
		k.Err = errors.New("larger than a DQS key")
	default:
		k.Key = antispam.Secret(strings.TrimSpace(string(data)))
	}
	return k
}
