package workerproc

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestWithRawFDsHoldsEveryFileAcrossConcurrentClose(t *testing.T) {
	a, b := socketPair(t)
	files := make([]*os.File, 2)
	want := make([]os.FileInfo, len(files))
	for i := range files {
		f, err := os.CreateTemp(t.TempDir(), "request")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		files[i] = f
		want[i], err = f.Stat()
		if err != nil {
			t.Fatal(err)
		}
	}

	var held []int
	err := withRawFDs(files, func(raw []int) error {
		held = append([]int(nil), raw...)
		closed := make(chan error, 1)
		go func() {
			var err error
			for _, f := range files {
				err = errors.Join(err, f.Close())
			}
			closed <- err
		}()
		// Regular-file Close returns before outstanding Control references
		// drain. Both raw descriptors must still be usable by sendmsg.
		select {
		case err := <-closed:
			if err != nil {
				return err
			}
		case <-time.After(5 * time.Second):
			return errors.New("regular-file Close blocked during Control")
		}
		buf := withHeader([]byte(`{"op":"work"}`))
		n, _, err := a.WriteMsgUnix(buf, syscall.UnixRights(raw...), nil)
		if err != nil {
			return err
		}
		if n != len(buf) {
			return fmt.Errorf("sent %d bytes, want %d", n, len(buf))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Check before recvmsg allocates descriptors and can reuse these slots.
	for _, fd := range held {
		if _, fdErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(fdErr, syscall.EBADF) {
			t.Errorf("caller descriptor %d survived Control: %v", fd, fdErr)
		}
	}
	frame, got, err := ReceiveFrame(b, Limits{MaxFrameBytes: 1024, MaxFDs: len(files)})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(got)
	if frame.Op != "work" || len(got) != len(files) {
		t.Fatalf("received frame=%+v descriptors=%d", frame, len(got))
	}
	for i, f := range got {
		info, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(info, want[i]) {
			t.Errorf("descriptor %d no longer refers to the caller's file", i)
		}
	}
}
