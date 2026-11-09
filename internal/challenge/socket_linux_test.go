//go:build linux

package challenge

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSocketDoesNotInheritNamedACLGrants(t *testing.T) {
	group, _ := ownGroup(t)
	dir := shortSocketDir(t)
	// The parent's default ACL grants a different uid access to new files.
	// chmod 0660 alone would enable that inherited grant on the socket.
	const undefined = 0xffffffff
	acl := []byte{2, 0, 0, 0}
	for _, e := range []struct {
		tag, perm uint16
		id        uint32
	}{{1, 7, undefined}, {2, 6, 65534}, {4, 7, undefined}, {16, 7, undefined}, {32, 0, undefined}} {
		acl = binary.LittleEndian.AppendUint16(acl, e.tag)
		acl = binary.LittleEndian.AppendUint16(acl, e.perm)
		acl = binary.LittleEndian.AppendUint32(acl, e.id)
	}
	if err := unix.Setxattr(dir, "system.posix_acl_default", acl, 0); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "c.sock")
	serveSocket(t, socketCfg(path, group), nil)
	if _, err := unix.Lgetxattr(path, "system.posix_acl_access", nil); !errors.Is(err, unix.ENODATA) {
		t.Fatalf("socket retains an inherited ACL grant: %v", err)
	}
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket permissions: %v, %v", fi, err)
	}
	after := make([]byte, len(acl))
	if n, err := unix.Lgetxattr(dir, "system.posix_acl_default", after); err != nil || n != len(acl) || !bytes.Equal(after, acl) {
		t.Fatalf("parent default ACL changed: %v", err)
	}
}
