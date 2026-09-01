//go:build linux

package daemon

import (
	"testing"

	"golang.org/x/sys/unix"
)

// stat(2) hands userspace a device number in the glibc encoding
// ((major<<8)|(minor&0xff)|((minor&~0xff)<<12)); the LSM program keys its
// map with the kernel's own dev_t ((major<<20)|minor). The two agree only for
// major 0, i.e. tmpfs and overlay -- exactly the filesystems test rigs use and
// production block devices never are. The map key must be the kernel form.
func TestKernelDeviceIDMatchesLSMEncoding(t *testing.T) {
	cases := []struct {
		major, minor uint32
	}{
		{0, 30},  // tmpfs: both encodings agree
		{8, 2},   // /dev/sda2
		{252, 1}, // virtio
		{259, 3}, // nvme
		{253, 5}, // device-mapper
		{8, 300}, // minor above 255 uses the high bits
		{4095, 1<<20 - 1},
	}
	for _, c := range cases {
		user := unix.Mkdev(c.major, c.minor)
		want := uint64(c.major)<<20 | uint64(c.minor)
		if got := kernelDeviceID(user); got != want {
			t.Errorf("kernelDeviceID(Mkdev(%d,%d)=%#x) = %#x, want %#x", c.major, c.minor, user, got, want)
		}
	}
}
