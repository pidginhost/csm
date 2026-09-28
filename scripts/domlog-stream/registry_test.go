package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRegistryRejectsFIFOWithoutReading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// Keep a writer connected so an attempted read cannot reach EOF.
	writer, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	const sentinel = "synthetic FIFO bytes"
	if _, err := writer.WriteString(sentinel); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		r, err := openRegistry(path, "0123456789ab")
		if r != nil {
			r.close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errRegistry) {
			t.Fatalf("FIFO: %v, want errRegistry", err)
		}
		buf := make([]byte, len(sentinel))
		n, err := syscall.Read(int(writer.Fd()), buf)
		if err != nil || string(buf[:n]) != sentinel {
			t.Fatalf("registry consumed FIFO bytes: read=%d err=%v", n, err)
		}
	case <-time.After(time.Second):
		writer.Close()
		<-done
		t.Fatal("registry read a FIFO instead of refusing it before reading")
	}
}

func TestRegistryRejectsUnsafeLock(t *testing.T) {
	for _, kind := range []string{"public", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "registry.json")
			lock := path + ".lock"
			if kind == "fifo" {
				if err := syscall.Mkfifo(lock, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(lock, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(lock, 0o666); err != nil {
					t.Fatal(err)
				}
			}
			r, err := openRegistry(path, "0123456789ab")
			if r != nil {
				r.close()
			}
			if !errors.Is(err, errRegistry) {
				t.Fatalf("unsafe lock accepted: %v", err)
			}
		})
	}
}

func TestRegistryRequiresDigestPrefix(t *testing.T) {
	for _, name := range []string{"dom-000001.example", "acct-000001", "e-0000000000000001"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "registry.json")
			raw := []byte(`{"format_version":1,"salt_fingerprint":"0123456789ab","names":{"` + name + `":"` + strings.Repeat("a", 64) + `"}}`)
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			r, err := openRegistry(path, "0123456789ab")
			if r != nil {
				r.close()
			}
			if !errors.Is(err, errRegistry) {
				t.Fatalf("name unrelated to its digest accepted: %v", err)
			}
			if !bytes.Equal(mustRead(t, path), raw) {
				t.Fatal("refusal changed registry history")
			}
		})
	}
}

func TestRegistrySaveRequiresDirectorySync(t *testing.T) {
	for _, syncFails := range []bool{false, true} {
		t.Run(strconv.FormatBool(syncFails), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "registry.json")
			r, err := openRegistry(path, "0123456789ab")
			if err != nil {
				t.Fatal(err)
			}
			defer r.close()
			if _, err = r.add(map[string]string{"acct-aaaaaa": strings.Repeat("a", 64)}); err != nil {
				t.Fatal(err)
			}
			called := false
			r.syncDir = func(dir string) error {
				called = true
				if dir != filepath.Dir(path) {
					t.Fatalf("synced %q, want registry directory", dir)
				}
				if !bytes.Contains(mustRead(t, path), []byte("acct-aaaaaa")) {
					t.Fatal("directory sync preceded registry replacement")
				}
				if syncFails {
					return errors.New("synthetic registry directory sync failure")
				}
				return syncRegistryDirectory(dir)
			}
			err = r.save()
			if !called || (syncFails && err != errRegistry) || (!syncFails && err != nil) {
				t.Fatalf("directory sync: called=%v err=%v failure=%v", called, err, syncFails)
			}
		})
	}
}
