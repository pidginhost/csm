package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func testRegistryName(salt []byte) string {
	digest := sha256.Sum256(salt)
	return "registry-" + hex.EncodeToString(digest[:]) + ".json"
}

func testRegistryPath(dir string) string {
	return filepath.Join(dir, testRegistryName(bytes.Repeat([]byte{0x42}, 32)))
}

func TestRegistryPathCannotForkHistory(t *testing.T) {
	logs, gz := defaultLogs()
	f := newFixture(t, logs, gz)
	f.registry = filepath.Join(f.dir, testRegistryName(bytes.Repeat([]byte{0x42}, 32)))
	if err := run(f.args(), io.Discard, testEnv()); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, f.registry)
	other := f
	other.registry = filepath.Join(f.dir, "another-registry.json")
	other.out, other.volume, other.manifest = f.out+".other", f.volume+".other", f.manifest+".other"
	// args adds --new-registry for the absent alternative filename.
	if err := run(other.args(), io.Discard, testEnv()); !errors.Is(err, errRegistryPlace) {
		t.Fatalf("second registry for the same salt: %v, want errRegistryPlace", err)
	}
	for _, path := range []string{other.registry, other.out, other.volume, other.manifest} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("refused conversion left a file: %v", err)
		}
	}
	if !bytes.Equal(before, mustRead(t, f.registry)) {
		t.Fatal("refusal changed registry history")
	}
}

func TestRegistryDirectoryIdentity(t *testing.T) {
	for _, escape := range []bool{false, true} {
		name := "same directory through a symlink"
		if escape {
			name = "symlink followed by dot-dot escapes the directory"
		}
		t.Run(name, func(t *testing.T) {
			logs, gz := defaultLogs()
			f := newFixture(t, logs, gz)
			base := testRegistryName(bytes.Repeat([]byte{0x42}, 32))
			if escape {
				elsewhere := filepath.Join(t.TempDir(), "child")
				if err := os.Mkdir(elsewhere, 0o700); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(f.dir, "escape")
				if err := os.Symlink(elsewhere, link); err != nil {
					t.Fatal(err)
				}
				// Do not clean this path: the kernel follows the symlink first.
				f.registry = link + "/../" + base
			} else {
				link := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(f.dir, link); err != nil {
					t.Fatal(err)
				}
				f.registry = filepath.Join(link, base)
			}
			err := run(f.args(), io.Discard, testEnv())
			if escape {
				if !errors.Is(err, errRegistryPlace) {
					t.Fatalf("registry escaped the salt directory: %v", err)
				}
				if _, statErr := os.Lstat(f.registry); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("refusal created an outside registry: %v", statErr)
				}
			} else if err != nil {
				t.Fatalf("registry in the same physical directory was refused: %v", err)
			}
		})
	}
}

func TestRegistrySaltAliasesUseSameHistory(t *testing.T) {
	for _, hardLink := range []bool{false, true} {
		name := "copy"
		if hardLink {
			name = "hard link"
		}
		t.Run(name, func(t *testing.T) {
			logs, gz := defaultLogs()
			f := newFixture(t, logs, gz)
			if err := run(f.args(), io.Discard, testEnv()); err != nil {
				t.Fatal(err)
			}
			before := mustRead(t, f.registry)
			alias := f.salt + ".alias"
			var err error
			if hardLink {
				err = os.Link(f.salt, alias)
			} else {
				err = os.WriteFile(alias, bytes.Repeat([]byte{0x42}, 32), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			f.salt = alias
			f.out, f.volume, f.manifest = f.out+".alias", f.volume+".alias", f.manifest+".alias"
			args := withoutRegistryFlag(f.args())
			if err := run(append(args, "--new-registry"), io.Discard, testEnv()); !errors.Is(err, errRegistry) {
				t.Fatalf("salt alias allowed a second initialization: %v", err)
			}
			if err := run(args, io.Discard, testEnv()); err != nil {
				t.Fatalf("salt alias could not reuse existing history: %v", err)
			}
			if !bytes.Equal(before, mustRead(t, f.registry)) {
				t.Fatal("salt alias changed registry history")
			}
		})
	}
}

func withoutRegistryFlag(args []string) []string {
	at := slices.Index(args, "--registry")
	return append(args[:at:at], args[at+2:]...)
}

type pausedRegistryFS struct {
	fileSystem
	inventory string
	entered   chan struct{}
	release   chan struct{}
}

func (f pausedRegistryFS) OpenFile(name string, flag int, mode os.FileMode) (file, error) {
	if name == f.inventory {
		close(f.entered)
		<-f.release
	}
	return f.fileSystem.OpenFile(name, flag, mode)
}

func TestRegistryInitializationExcludesConcurrentAliases(t *testing.T) {
	logs, gz := defaultLogs()
	f := newFixture(t, logs, gz)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(f.dir, alias); err != nil {
		t.Fatal(err)
	}
	other := f
	other.salt = filepath.Join(alias, "salt")
	other.registry = filepath.Join(alias, filepath.Base(f.registry))
	other.out, other.volume, other.manifest = f.out+".other", f.volume+".other", f.manifest+".other"
	// Both attempts decide to initialize before either has saved a registry.
	firstArgs, otherArgs := withoutRegistryFlag(f.args()), other.args()
	paused := pausedRegistryFS{fileSystem: osFS{}, inventory: f.inventory, entered: make(chan struct{}), release: make(chan struct{})}
	e := testEnv()
	e.fs = paused
	done := make(chan error, 1)
	go func() { done <- run(firstArgs, io.Discard, e) }()
	defer close(paused.release)
	select {
	case <-paused.entered:
	case err := <-done:
		t.Fatalf("first run failed before reading inventory: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("first run did not reach inventory")
	}
	if err := run(otherArgs, io.Discard, testEnv()); !errors.Is(err, errRegistry) {
		t.Fatalf("concurrent alias did not share the lock: %v", err)
	}
	// Release without closing yet, so the deferred close also covers failures.
	paused.release <- struct{}{}
	if err := <-done; err != nil {
		t.Fatalf("first initialization failed: %v", err)
	}
	before := mustRead(t, f.registry)
	if err := run(otherArgs, io.Discard, testEnv()); !errors.Is(err, errRegistry) {
		t.Fatalf("second initialization after lock release: %v", err)
	}
	for _, path := range []string{other.out, other.volume, other.manifest} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("refused conversion published output: %v", err)
		}
	}
	if !bytes.Equal(before, mustRead(t, f.registry)) {
		t.Fatal("second initialization replaced registry history")
	}
}
