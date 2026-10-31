package yaraipc

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDecodeScanReply(t *testing.T) {
	matches, err := DecodeScanReply([]byte(`{"matches":[{"rule":"hit","meta":{"severity":"high"}}]}`))
	if err != nil || len(matches) != 1 || matches[0].RuleName != "hit" || matches[0].Meta["severity"] != "high" {
		t.Fatalf("decode = %+v, %v", matches, err)
	}
	clean, err := DecodeScanReply([]byte(`{"matches":[]}`))
	if err != nil || clean == nil || len(clean) != 0 {
		t.Fatalf("clean decode = %#v, %v; want an empty non-nil slice", clean, err)
	}
}

func TestDecodeScanReplyRejectsMalformed(t *testing.T) {
	for name, payload := range map[string]string{
		"missing":      ``,
		"null":         `null`,
		"null-matches": `{"matches":null}`,
		"empty":        `{}`,
		"ping":         `{"alive":true}`,
		"unknown":      `{"matches":[],"partial":true}`,
		"wrong-type":   `{"matches":false}`,
		"trailing":     `{"matches":[]} {"matches":[]}`,
		"invalid-utf8": "{\"matches\":[{\"rule\":\"\xff\"}]}",
	} {
		if m, err := DecodeScanReply([]byte(payload)); err == nil {
			t.Errorf("%s: malformed reply accepted: %+v", name, m)
		}
	}
}

func TestReopenReadOnlyRejectsNonRegular(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if f, reopenErr := ReopenReadOnly(r); reopenErr == nil {
		_ = f.Close()
		t.Fatal("a pipe was reopened")
	}
	path := filepath.Join(t.TempDir(), "part")
	if err = os.WriteFile(path, []byte("part"), 0o600); err != nil {
		t.Fatal(err)
	}
	closed, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()
	for _, f := range []*os.File{nil, closed} {
		if ro, err := ReopenReadOnly(f); err == nil {
			_ = ro.Close()
			t.Error("an unreadable source was reopened")
		}
	}
}

func TestReopenReadOnlyKeepsCallerFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "part")
	if err := os.WriteFile(path, []byte("part"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	flags := func(f *os.File) int {
		t.Helper()
		rc, connErr := f.SyscallConn()
		if connErr != nil {
			t.Fatal(connErr)
		}
		var fl int
		var flErr error
		if ctlErr := rc.Control(func(fd uintptr) { fl, flErr = unix.FcntlInt(fd, unix.F_GETFL, 0) }); ctlErr != nil || flErr != nil {
			t.Fatalf("flags: %v, %v", ctlErr, flErr)
		}
		return fl
	}
	before := flags(f)
	ro, err := ReopenReadOnly(f)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if after := flags(f); after != before {
		t.Fatalf("caller flags changed: %#x -> %#x", before, after)
	}
	if flags(ro)&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatal("reopened descriptor is writable")
	}
}
