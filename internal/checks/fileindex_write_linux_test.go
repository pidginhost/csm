//go:build linux

package checks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestWriteIndexDoesNotPromoteFailedWrites(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
	}{{"flush", 10}, {"write", 8192}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "index")
			if err := os.WriteFile(path, []byte("previous\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/dev/full", path+".tmp"); err != nil {
				t.Fatal(err)
			}
			if err := writeIndex(path, []string{strings.Repeat("x", tc.size)}); !errors.Is(err, syscall.ENOSPC) {
				t.Fatalf("write/flush error lost: %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "previous\n" {
				t.Fatalf("failed temporary output replaced baseline: %q %v", data, err)
			}
		})
	}
}
