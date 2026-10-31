//go:build linux

package yaraipc

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// memfdCreate is a seam so tests can make memfd creation fail.
var memfdCreate = unix.MemfdCreate

// SealedMemfd copies data into a memory-backed file and seals it, so the
// worker that receives it can read the bytes but cannot change them.
func SealedMemfd(name string, data []byte) (*os.File, error) {
	f, err := newMemfd(name)
	if err != nil {
		return nil, err
	}
	if _, err = f.Write(data); err == nil {
		err = sealFile(f)
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("yaraipc: fill %s memfd: %w", name, err)
	}
	return f, nil
}

// CopySealedMemfd copies the first size bytes of src into a new sealed memfd
// owned by this process, so nothing another process kept open can change it.
// A source shorter than size is an error.
func CopySealedMemfd(name string, src *os.File, size int64) (*os.File, error) {
	f, err := newMemfd(name)
	if err != nil {
		return nil, err
	}
	n, err := io.Copy(f, io.NewSectionReader(src, 0, size))
	if err == nil && n != size {
		err = fmt.Errorf("copied %d of %d bytes: %w", n, size, io.ErrUnexpectedEOF)
	}
	if err == nil {
		err = sealFile(f)
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("yaraipc: copy %s memfd: %w", name, err)
	}
	return f, nil
}

func newMemfd(name string) (*os.File, error) {
	fd, err := memfdCreate(name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("yaraipc: create %s memfd: %w", name, err)
	}
	return os.NewFile(uintptr(fd), name), nil // #nosec G115 -- memfd_create returned a valid descriptor.
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
