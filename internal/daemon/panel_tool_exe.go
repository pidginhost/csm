package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// deletedExeSuffix is what procfs appends to /proc/<pid>/exe once the binary
// behind a running process has been unlinked.
const deletedExeSuffix = " (deleted)"

// panelToolExeTrusted reports whether exe is an executable the control panel
// installed and only root can replace: a regular file inside one of roots,
// owned by root, writable by nobody else.
//
// Provenance reads the resolved exe rather than comm because comm is set by
// the process itself -- any user can run prctl(PR_SET_NAME, "upcp"). An exe
// path cannot be faked without actually executing that file, and a root-owned
// file with no group or other write bit cannot be put under the panel root by
// an unprivileged attacker. A binary unlinked after it started no longer has
// inspectable bytes behind it, so it proves nothing and is refused.
func panelToolExeTrusted(exe string, roots []string, mode os.FileMode, uid uint32) bool {
	if len(roots) == 0 || uid != 0 {
		return false
	}
	if !mode.IsRegular() || mode.Perm()&0o022 != 0 {
		return false
	}
	return exeInPanelRoot(exe, roots)
}

// exeInPanelRoot reports whether exe resolves inside one of roots. Split out
// of panelToolExeTrusted so the walker can reject a path before stat()ing it:
// an ancestor's exe can point anywhere, including a hung network or FUSE
// mount, and a path test costs nothing.
func exeInPanelRoot(exe string, roots []string) bool {
	if strings.HasSuffix(exe, deletedExeSuffix) || !filepath.IsAbs(exe) {
		return false
	}
	clean := filepath.Clean(exe)
	for _, root := range roots {
		if strings.HasPrefix(clean, filepath.Clean(root)+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// exeStat resolves an executable path to the mode and owner uid used for the
// trust decision. A var so tests can describe a root-owned binary they cannot
// create.
var exeStat = statExe

func statExe(path string) (os.FileMode, uint32, error) {
	// Stat, not Lstat: procfs hands back the kernel's resolved path for the
	// running binary, and a root-owned target is one only root could place
	// whichever way the path reached it.
	fi, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errNoStat
	}
	return fi.Mode(), st.Uid, nil
}

var errNoStat = errors.New("daemon: file info carries no owner")
