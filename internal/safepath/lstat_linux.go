//go:build linux

package safepath

import (
	"os"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type descriptorFileInfo struct {
	name string
	stat syscall.Stat_t
}

func (i *descriptorFileInfo) Name() string       { return i.name }
func (i *descriptorFileInfo) Size() int64        { return i.stat.Size }
func (i *descriptorFileInfo) ModTime() time.Time { return time.Unix(i.stat.Mtim.Sec, i.stat.Mtim.Nsec) }
func (i *descriptorFileInfo) IsDir() bool        { return i.Mode().IsDir() }
func (i *descriptorFileInfo) Sys() any           { return &i.stat }

func (i *descriptorFileInfo) Mode() os.FileMode {
	mode := os.FileMode(i.stat.Mode & 0777)
	switch i.stat.Mode & syscall.S_IFMT {
	case syscall.S_IFBLK:
		mode |= os.ModeDevice
	case syscall.S_IFCHR:
		mode |= os.ModeDevice | os.ModeCharDevice
	case syscall.S_IFDIR:
		mode |= os.ModeDir
	case syscall.S_IFIFO:
		mode |= os.ModeNamedPipe
	case syscall.S_IFLNK:
		mode |= os.ModeSymlink
	case syscall.S_IFSOCK:
		mode |= os.ModeSocket
	}
	if i.stat.Mode&syscall.S_ISGID != 0 {
		mode |= os.ModeSetgid
	}
	if i.stat.Mode&syscall.S_ISUID != 0 {
		mode |= os.ModeSetuid
	}
	if i.stat.Mode&syscall.S_ISVTX != 0 {
		mode |= os.ModeSticky
	}
	return mode
}

// Lstat reads a child entry without opening it. This remains usable while the
// child inode has an exclusive lease and still keeps lookup relative to the
// pinned directory descriptor.
func (d *Dir) Lstat(name string) (os.FileInfo, error) {
	if !validName(name) {
		return nil, &os.PathError{Op: "fstatat", Path: name, Err: syscall.EINVAL}
	}
	var raw unix.Stat_t
	err := unix.Fstatat(fileFD(d.file), name, &raw, unix.AT_SYMLINK_NOFOLLOW)
	runtime.KeepAlive(d)
	if err != nil {
		return nil, &os.PathError{Op: "fstatat", Path: name, Err: err}
	}
	stat := syscall.Stat_t{
		Dev: raw.Dev, Ino: raw.Ino, Nlink: raw.Nlink, Mode: raw.Mode,
		Uid: raw.Uid, Gid: raw.Gid, Rdev: raw.Rdev, Size: raw.Size,
		Blksize: raw.Blksize, Blocks: raw.Blocks,
		Atim: syscall.Timespec{Sec: raw.Atim.Sec, Nsec: raw.Atim.Nsec},
		Mtim: syscall.Timespec{Sec: raw.Mtim.Sec, Nsec: raw.Mtim.Nsec},
		Ctim: syscall.Timespec{Sec: raw.Ctim.Sec, Nsec: raw.Ctim.Nsec},
	}
	return &descriptorFileInfo{name: name, stat: stat}, nil
}
