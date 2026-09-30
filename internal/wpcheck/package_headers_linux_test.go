package wpcheck

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPackageHeaderRejectsNonregularFilesWithoutBlocking(t *testing.T) {
	for _, kind := range []string{"directory", "fifo", "symlink-fifo", "device"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			header := filepath.Join(root, "header.php")
			switch kind {
			case "directory":
				if err := os.Mkdir(header, 0o755); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(header, 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink-fifo":
				fifo := filepath.Join(root, "fifo")
				if err := unix.Mkfifo(fifo, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(fifo, header); err != nil {
					t.Fatal(err)
				}
			case "device":
				if err := os.Symlink("/dev/zero", header); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() {
				_, err := readPackageHeader(header)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("nonregular file supplied a package header")
				}
			case <-time.After(2 * time.Second):
				if kind == "fifo" || kind == "symlink-fifo" {
					writer, err := os.OpenFile(header, os.O_WRONLY|unix.O_NONBLOCK, 0)
					if err != nil {
						t.Fatal(err)
					}
					_ = writer.Close()
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Fatal("header read did not stop after releasing the FIFO")
					}
				}
				t.Fatal("nonregular header blocked the reader")
			}
		})
	}
}
