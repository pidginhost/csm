package stalwartapi

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/atomicio"
)

// ErrNoKeyFile reports that the API key file does not exist.
var ErrNoKeyFile = errors.New("no Stalwart API key file")

// maxKeyFileBytes bounds the read: a key is 42 characters.
const maxKeyFileBytes = 256

// keyFileOwner is the uid that must own the key file.
var keyFileOwner uint32

// SetKeyFileOwnerForTest lets tests that do not run as root read key files
// they wrote.
func SetKeyFileOwnerForTest(uid uint32) (restore func()) {
	old := keyFileOwner
	keyFileOwner = uid
	return func() { keyFileOwner = old }
}

// ReadKeyFile reads the API key from path. The file must be a regular file
// owned by root and closed to group and others; a final symlink is not
// followed. Errors name the path and never the content.
func ReadKeyFile(path string) (string, error) {
	// #nosec G304 -- the operator's configured key path, opened read-only without following a final link.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("%s: %w", path, ErrNoKeyFile)
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s: not a regular file", path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != keyFileOwner {
		return "", fmt.Errorf("%s: must be owned by root", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("%s: mode %04o is open to group or others, want 0600", path, perm)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	if len(data) > maxKeyFileBytes {
		return "", fmt.Errorf("%s: larger than %d bytes", path, maxKeyFileBytes)
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", fmt.Errorf("%s: empty", path)
	}
	return key, nil
}

// WriteKeyFile stores secret at path with mode 0600, replacing any file
// there in one rename so a reader never sees a partial key.
func WriteKeyFile(path, secret string) error {
	return atomicio.AtomicWrite(path, 0o600, []byte(secret))
}
