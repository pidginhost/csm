package checks

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
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
	return readHtaccessFileBounded(f)
}

// readTenantHtaccessBounded is readHtaccessBounded for a caller acting on the
// tenant's behalf as root. Every tenant-controlled directory is opened without
// following symlinks, so a path replacement cannot redirect a privileged read
// outside the passwd home. Special files cannot block the read.
func readTenantHtaccessBounded(home, dir string) (data []byte, ok bool, err error) {
	var f *os.File
	if _, production := osFS.(realOS); production {
		f, err = openTenantHtaccess(home, dir)
	} else {
		f, err = openTenantRegularFile(filepath.Join(dir, ".htaccess"))
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	return readHtaccessFileBounded(f)
}

func openTenantHtaccess(home, dir string) (*os.File, error) {
	rel, err := filepath.Rel(home, dir)
	if err != nil || !filepath.IsAbs(home) || !filepath.IsLocal(rel) {
		return nil, os.ErrPermission
	}
	const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	fd, err := unix.Open(home, dirFlags, 0)
	if err != nil {
		// A missing directory is not an absent .htaccess. The caller must
		// stop instead of falling back to a handler in a surviving ancestor.
		return nil, errNonRegularFile
	}
	defer func() { _ = unix.Close(fd) }()
	if rel != "." {
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			next, openErr := unix.Openat(fd, part, dirFlags, 0)
			if openErr != nil {
				return nil, errNonRegularFile
			}
			_ = unix.Close(fd)
			fd = next
		}
	}
	fileFD, err := unix.Openat(fd, ".htaccess", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	// #nosec G115 -- unix.Openat returned a non-negative descriptor because err is nil.
	return os.NewFile(uintptr(fileFD), filepath.Join(dir, ".htaccess")), nil
}

func readHtaccessFileBounded(f *os.File) (data []byte, ok bool, err error) {
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
