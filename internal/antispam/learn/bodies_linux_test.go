package learn

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCommitAtomicallyMovesStagedBody(t *testing.T) {
	b := testBodies(t)
	s, err := b.Stage([]byte("anchor body"))
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if _, watchErr := unix.InotifyAddWatch(fd, b.Dir, unix.IN_MOVED_FROM|unix.IN_MOVED_TO|unix.IN_CREATE|unix.IN_DELETE); watchErr != nil {
		t.Fatal(watchErr)
	}
	if commitErr := b.Commit(s, 1); commitErr != nil {
		t.Fatal(commitErr)
	}
	buf := make([]byte, 4096)
	n, err := unix.Read(fd, buf)
	if err != nil {
		t.Fatal(err)
	}
	var masks, cookies []uint32
	for off := 0; off+unix.SizeofInotifyEvent <= n; {
		masks = append(masks, binary.NativeEndian.Uint32(buf[off+4:]))
		cookies = append(cookies, binary.NativeEndian.Uint32(buf[off+8:]))
		off += unix.SizeofInotifyEvent + int(binary.NativeEndian.Uint32(buf[off+12:]))
	}
	if len(masks) != 2 || masks[0] != unix.IN_MOVED_FROM || masks[1] != unix.IN_MOVED_TO || cookies[0] == 0 || cookies[0] != cookies[1] {
		t.Fatalf("commit was not one rename: masks=%v cookies=%v", masks, cookies)
	}
}

func TestReadRejectsFIFOWithoutBlocking(t *testing.T) {
	b := testBodies(t)
	if err := os.Mkdir(b.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(b.Dir, BodyName(1))
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		body, err := b.Read(1, 0, "")
		if body != nil {
			err = errors.New("returned bytes from a FIFO")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrBodyInvalid) {
			t.Fatalf("FIFO read: %v", err)
		}
	case <-time.After(time.Second):
		// Release a blocked open so the regression cannot leak a goroutine.
		f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		<-done
		t.Fatal("body read blocked opening a FIFO")
	}
}

func TestStageSetsExactFileMode(t *testing.T) {
	b := testBodies(t)
	if err := os.Mkdir(b.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mask := syscall.Umask(0o200)
	defer syscall.Umask(mask)
	s, err := b.Stage([]byte("anchor body"))
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(b.Dir, s.Name)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("staged body lacks mode 0600: %v, %v", info, err)
	}
}
