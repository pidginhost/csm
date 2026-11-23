package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func phpExecutableTrusted(root string, proc phpProcessFiles, exe string) bool {
	info, err := phpProcessExeInfo(proc)
	if err != nil {
		return false
	}
	return trustedPHPExecutable(exe, info, func(path string) (os.FileInfo, error) {
		return os.Lstat(filepath.Join(root, path))
	})
}

func phpProcessExeInfo(proc phpProcessFiles) (os.FileInfo, error) {
	// Root.Stat cannot follow the exe magic link outside its root. Open the
	// pinned directory itself and follow through its fd, never a reused PID.
	dir, err := proc.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	return os.Stat(fmt.Sprintf("/proc/self/fd/%d/exe", dir.Fd()))
}

// Ownership of the inode alone is insufficient: users can hard-link a root
// binary into their own directory and choose its name. Check every ancestor
// and match the running inode to exclude private mount namespaces and swaps.
func trustedPHPExecutable(exe string, running os.FileInfo, lstat func(string) (os.FileInfo, error)) bool {
	if !filepath.IsAbs(exe) || filepath.Clean(exe) != exe || strings.HasSuffix(exe, " (deleted)") {
		return false
	}
	runningStat, ok := running.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	path := "/"
	parts := strings.Split(strings.TrimPrefix(exe, "/"), "/")
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			path = filepath.Join(path, parts[i])
		}
		info, err := lstat(path)
		if err != nil {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
		if i == len(parts)-1 {
			return info.Mode().IsRegular() && st.Dev == runningStat.Dev && st.Ino == runningStat.Ino
		}
		if !info.IsDir() {
			return false
		}
	}
	return false
}
