//go:build !linux

package checks

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"syscall"
)

// accountDirIncarnation names the home directory at path by its device and
// inode. Without a birth time an inode reused by a replacement goes unseen;
// production hosts are Linux.
func accountDirIncarnation(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("account home has no inode number")
	}
	b := binary.BigEndian.AppendUint64(nil, uint64(st.Dev)) // #nosec G115 -- bit pattern only.
	b = binary.BigEndian.AppendUint64(b, st.Ino)
	sum := sha256.Sum256(b)
	return "fs:" + hex.EncodeToString(sum[:16]), nil
}
