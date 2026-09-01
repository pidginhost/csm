//go:build linux

package daemon

import "golang.org/x/sys/unix"

// kernelDeviceID converts the device number stat(2) reports, which uses the
// glibc encoding (major<<8)|(minor&0xff)|((minor&~0xff)<<12), into the
// kernel's own dev_t (major<<20)|minor. That is what an LSM program reads from
// inode->i_sb->s_dev, so a BPF map keyed by device must use this form. The two
// encodings agree only for major 0 (tmpfs, overlay), which is why a map keyed
// with the raw stat value works in test rigs and misses every file on a real
// block device.
func kernelDeviceID(statDev uint64) uint64 {
	return uint64(unix.Major(statDev))<<20 | uint64(unix.Minor(statDev))
}
