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
	const undefined = 0xffffffff
	acl := []byte{2, 0, 0, 0}
	for _, e := range []struct {
		tag, perm uint16
		id        uint32
	}{{0x01, 6, undefined}, {0x02, 4, uint32(uid)}, {0x04, 4, undefined}, {0x10, 4, undefined}, {0x20, 4, undefined}} {
		acl = binary.LittleEndian.AppendUint16(acl, e.tag)
		acl = binary.LittleEndian.AppendUint16(acl, e.perm)
		acl = binary.LittleEndian.AppendUint32(acl, e.id)
	}
	return unix.Setxattr(p, "system.posix_acl_access", acl, 0)
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
