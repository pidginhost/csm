package platform

import (
	"os"
	"syscall"
	"testing"
	"time"
)

type phpExecutableInfo struct {
	mode os.FileMode
	stat syscall.Stat_t
}

func (i phpExecutableInfo) Name() string       { return "fixture" }
func (i phpExecutableInfo) Size() int64        { return 1 }
func (i phpExecutableInfo) Mode() os.FileMode  { return i.mode }
func (i phpExecutableInfo) ModTime() time.Time { return time.Time{} }
func (i phpExecutableInfo) IsDir() bool        { return i.mode.IsDir() }
func (i phpExecutableInfo) Sys() any           { return &i.stat }

func TestTrustedPHPExecutable(t *testing.T) {
	for _, tc := range []struct {
		name, path, changed         string
		uid                         uint32
		mode                        os.FileMode
		wrongInode, statError, want bool
	}{
		{name: "installed", path: "/usr/bin/service", want: true},
		{name: "user binary", path: "/usr/bin/service", changed: "/usr/bin/service", uid: 33, mode: 0755},
		{name: "user hard link", path: "/usr/bin/service", changed: "/usr/bin", uid: 33, mode: os.ModeDir | 0755},
		{name: "writable file", path: "/usr/bin/service", changed: "/usr/bin/service", mode: 0775},
		{name: "writable directory", path: "/usr/bin/service", changed: "/usr", mode: os.ModeDir | 0777},
		{name: "writable root", path: "/usr/bin/service", changed: "/", mode: os.ModeDir | 0775},
		{name: "directory symlink", path: "/usr/bin/service", changed: "/usr/bin", mode: os.ModeSymlink | 0755},
		{name: "file symlink", path: "/usr/bin/service", changed: "/usr/bin/service", mode: os.ModeSymlink | 0755},
		{name: "special file", path: "/usr/bin/service", changed: "/usr/bin/service", mode: os.ModeNamedPipe | 0755},
		{name: "different namespace inode", path: "/usr/bin/service", wrongInode: true},
		{name: "missing metadata", path: "/usr/bin/service", statError: true},
		{name: "deleted", path: "/usr/bin/service (deleted)"},
		{name: "relative", path: "usr/bin/service"},
		{name: "unclean", path: "/usr/bin/../service"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			running := phpExecutableInfo{mode: 0755, stat: syscall.Stat_t{Dev: 1, Ino: 42}}
			lstat := func(path string) (os.FileInfo, error) {
				if tc.statError {
					return nil, os.ErrPermission
				}
				info := running
				if path != tc.path {
					info.mode = os.ModeDir | 0755
				}
				if path == tc.changed {
					info.stat.Uid, info.mode = tc.uid, tc.mode
				}
				if tc.wrongInode {
					info.stat.Ino++
				}
				return info, nil
			}
			if got := trustedPHPExecutable(tc.path, running, lstat); got != tc.want {
				t.Fatalf("trusted = %v, want %v", got, tc.want)
			}
		})
	}
}
