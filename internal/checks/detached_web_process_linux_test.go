//go:build linux

package checks

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestUnixListenerLive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "php pool.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	assertPath := func(want string) {
		t.Helper()
		for _, got := range unixListeners() {
			if got == want {
				return
			}
		}
		t.Fatalf("live listener %q absent from proc table", want)
	}
	assertPath(path)
	// Unlinking a listening socket does not remove its original proc name.
	if removeErr := os.Remove(path); removeErr != nil {
		t.Fatal(removeErr)
	}
	assertPath(path)
	abstract := "@csm " + filepath.Base(filepath.Dir(path)) + " " + filepath.Base(path)
	other, err := net.Listen("unix", abstract)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := other.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	assertPath(abstract)
}
