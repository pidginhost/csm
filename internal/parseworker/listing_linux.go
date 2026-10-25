package parseworker

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const listingSeals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK

// sealFile seals a memfd against writes, growth and shrinkage.
func sealFile(f *os.File) error {
	_, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, listingSeals)
	return err
}

// checkSealed verifies a memfd carries the seals sealFile adds.
func checkSealed(f *os.File) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var seals int
	var sealErr error
	if err := raw.Control(func(fd uintptr) {
		seals, sealErr = unix.FcntlInt(fd, unix.F_GET_SEALS, 0)
	}); err != nil {
		return err
	}
	if sealErr != nil {
		return fmt.Errorf("listing seals: %w", sealErr)
	}
	if seals&listingSeals != listingSeals {
		return errors.New("listing is not sealed against writes and size changes")
	}
	return nil
}
