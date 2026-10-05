//go:build linux

package checks

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"golang.org/x/sys/unix"
)

// accountDirIncarnation names the home directory at path by its device,
// inode and birth time. Its owner can change neither, while a directory
// created in its place has another inode or birth time. The mount ID stays
// out: it names the mount instance, which the service's own mount namespace
// renews at each start.
func accountDirIncarnation(path string) (string, error) {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_TYPE|unix.STATX_INO|unix.STATX_BTIME, &st); err != nil {
		return "", err
	}
	return accountStatxIncarnation(st)
}

func accountStatxIncarnation(st unix.Statx_t) (string, error) {
	if st.Mask&unix.STATX_INO == 0 {
		return "", errors.New("account home has no inode number")
	}
	if st.Mask&unix.STATX_TYPE == 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return "", errors.New("account home is not a directory")
	}
	if st.Mask&unix.STATX_BTIME == 0 {
		return "", errors.New("account home has no birth time")
	}
	return statxIncarnation(st), nil
}

// statxIncarnation digests the identity fields of st, so the token stays
// short.
func statxIncarnation(st unix.Statx_t) string {
	b := binary.BigEndian.AppendUint32(nil, st.Dev_major)
	b = binary.BigEndian.AppendUint32(b, st.Dev_minor)
	b = binary.BigEndian.AppendUint64(b, st.Ino)
	if st.Mask&unix.STATX_BTIME != 0 {
		b = binary.BigEndian.AppendUint64(b, uint64(st.Btime.Sec)) // #nosec G115 -- bit pattern only.
		b = binary.BigEndian.AppendUint32(b, st.Btime.Nsec)
	}
	sum := sha256.Sum256(b)
	return "fs:" + hex.EncodeToString(sum[:16])
}
