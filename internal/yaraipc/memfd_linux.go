//go:build linux

package yaraipc

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// memfdCreate is a seam so tests can make memfd creation fail.
var memfdCreate = unix.MemfdCreate

// sealedMemfd copies data into a memory-backed file and seals it, so the
// worker that receives it can read the bytes but cannot change them.
func sealedMemfd(data []byte) (*os.File, error) {
	fd, err := memfdCreate("csm-yara-scan", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("yaraipc: create scan memfd: %w", err)
	}
	f := os.NewFile(uintptr(fd), "csm-yara-scan") // #nosec G115 -- memfd_create returned a valid descriptor.
	if _, err = f.Write(data); err == nil {
		err = sealFile(f)
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("yaraipc: fill scan memfd: %w", err)
	}
	return f, nil
}

func sealFile(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var sealErr error
	if err = rc.Control(func(fd uintptr) {
		_, sealErr = unix.FcntlInt(fd, unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL)
	}); err != nil {
		return err
	}
	return sealErr
}
