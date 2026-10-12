//go:build linux

package hostfacts

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// setUserACL grants uid read access through a POSIX access ACL, written in
// the kernel's xattr format (version 2, then tag/perm/id entries).
func setUserACL(p string, uid int) error {
	return setACL(p, "system.posix_acl_access", uid, 4)
}

func setACL(p, attribute string, uid int, permission uint16) error {
	const undefined = 0xffffffff
	acl := []byte{2, 0, 0, 0}
	for _, e := range []struct {
		tag, perm uint16
		id        uint32
	}{{0x01, 6, undefined}, {0x02, permission, uint32(uid)}, {0x04, 4, undefined}, {0x10, permission | 4, undefined}, {0x20, 4, undefined}} {
		acl = binary.LittleEndian.AppendUint16(acl, e.tag)
		acl = binary.LittleEndian.AppendUint16(acl, e.perm)
		acl = binary.LittleEndian.AppendUint32(acl, e.id)
	}
	return unix.Setxattr(p, attribute, acl, 0)
}

func TestPathFactsReportsDefaultACL(t *testing.T) {
	d := t.TempDir()
	if err := setACL(d, "system.posix_acl_default", 65534, 6); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Lgetxattr(d, "system.posix_acl_access", nil); !errors.Is(err, unix.ENODATA) {
		t.Fatalf("directory unexpectedly has an access ACL: %v", err)
	}
	got, err := pathFacts(d)
	if err != nil || !got.ExtACL {
		t.Fatalf("default ACL not reported: %+v, %v", got, err)
	}
	child := filepath.Join(d, "child")
	if err := os.WriteFile(child, nil, 0o660); err != nil {
		t.Fatal(err)
	}
	if inherited, err := pathFacts(child); err != nil || !inherited.ExtACL {
		t.Fatalf("child ACL not inherited: %+v, %v", inherited, err)
	}
}

func TestPathFactsReportsExtendedACL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := setUserACL(p, 65534); errors.Is(err, unix.EOPNOTSUPP) {
		t.Skip("the test filesystem has no POSIX ACL support")
	} else if err != nil {
		t.Fatal(err)
	}
	got, err := pathFacts(p)
	if err != nil || !got.ExtACL {
		t.Fatalf("got %+v, %v; want ExtACL", got, err)
	}
}

func TestReadTextRejectsFIFOWithoutWaitingForWriter(t *testing.T) {
	p := filepath.Join(t.TempDir(), "exim.conf.local")
	if err := unix.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readText(p)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || err.Error() != "configuration is not a regular file" {
			t.Fatalf("readText FIFO = %v; want a non-regular file error", err)
		}
	case <-time.After(2 * time.Second):
		// Release a blocked reader so the regression leaves no goroutine.
		writer, err := os.OpenFile(p, os.O_WRONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		<-done
		t.Fatal("readText waited for a writer before rejecting the FIFO")
	}
}

func TestReadRegularContentRejectsFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readRegularContent(p); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted as a regular file")
		}
	case <-time.After(time.Second):
		// Release a blocking reader so a failed regression cannot leak it.
		fd, err := unix.Open(p, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if err == nil {
			_ = unix.Close(fd)
		}
		t.Fatal("content read blocked on a FIFO")
	}
}
