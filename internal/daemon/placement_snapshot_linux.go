//go:build linux

package daemon

import (
	"crypto/sha256"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/checks"
)

type analysisSnapshot struct {
	key  analysisKey
	stat unix.Stat_t
}

// Content, not mtime, proves equivalence across renames. The existing complete
// content budget bounds this optimization; larger files always get analysed.
func snapshotForAnalysis(fd int, class string) (analysisSnapshot, bool) {
	var st unix.Stat_t
	if class == "" || unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o111 != 0 {
		return analysisSnapshot{}, false
	}
	data := readExactSize(st.Size, checks.MaxInertPHPScanBytes, func(p []byte, off int64) (int, error) {
		return unix.Pread(fd, p, off)
	})
	if data == nil {
		return analysisSnapshot{}, false
	}
	snapshot := analysisSnapshot{
		key: analysisKey{
			Dev: uint64(st.Dev), Ino: st.Ino, Size: st.Size, MtimeNs: st.Mtim.Nano(),
			Mode: st.Mode, Uid: st.Uid, Gid: st.Gid, Class: class, Digest: sha256.Sum256(data),
		},
		stat: st,
	}
	return snapshot, snapshot.unchanged(fd)
}

// Ctime is excluded from the cache key because a rename changes it. During a
// scan it must stay fixed, including when a writer changes bytes and puts them
// back before the scan ends.
func (s analysisSnapshot) unchanged(fd int) bool {
	var after unix.Stat_t
	return unix.Fstat(fd, &after) == nil && sameReadSnapshot(s.stat, after) &&
		s.stat.Mode == after.Mode && s.stat.Uid == after.Uid && s.stat.Gid == after.Gid
}
