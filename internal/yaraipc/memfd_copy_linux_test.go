//go:build linux

package yaraipc

import (
	"io"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCopySealedMemfdSealsCopy(t *testing.T) {
	src, err := SealedMemfd("csm-yara-test", []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := CopySealedMemfd("csm-yara-copy", src, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	data, err := io.ReadAll(io.NewSectionReader(dst, 0, 16))
	if err != nil || string(data) != "abc" {
		t.Fatalf("copy = %q, %v", data, err)
	}
	seals, err := unix.FcntlInt(dst.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL; seals&want != want {
		t.Fatalf("seals = %#x, want %#x", seals, want)
	}
}

func TestCopySealedMemfdRejectsShortSource(t *testing.T) {
	src, err := SealedMemfd("csm-yara-test", []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if dst, err := CopySealedMemfd("csm-yara-copy", src, 4); err == nil {
		_ = dst.Close()
		t.Fatal("a source shorter than size was copied")
	}
}

func TestSealedMemfdFailsWhenMemfdUnavailable(t *testing.T) {
	prev := memfdCreate
	memfdCreate = func(string, int) (int, error) { return -1, unix.EMFILE }
	t.Cleanup(func() { memfdCreate = prev })
	if f, err := SealedMemfd("csm-yara-scan", []byte("payload")); err == nil {
		_ = f.Close()
		t.Fatal("a memfd was made while memfd_create fails")
	}
}
