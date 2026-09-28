package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestOperatorInputsAreClosed covers the inventory, labels and bot evidence:
// each must be a regular file in its closed JSON form.
func TestOperatorInputsAreClosed(t *testing.T) {
	inputs := []struct {
		name string
		path func(*fixture) *string
		want cliError
	}{
		{"inventory", func(f *fixture) *string { return &f.inventory }, errInventory},
		{"labels", func(f *fixture) *string { return &f.labels }, errLabels},
		{"bot evidence", func(f *fixture) *string { return &f.evidence }, errBotEvidence},
	}
	for _, in := range inputs {
		t.Run(in.name+"/files", func(t *testing.T) {
			for kind, replace := range map[string]func(path string) (string, error){
				"symlink": func(path string) (string, error) {
					target := path + ".target"
					if err := os.Rename(path, target); err != nil {
						return "", err
					}
					return path, os.Symlink(target, path)
				},
				"directory": func(path string) (string, error) {
					if err := os.Remove(path); err != nil {
						return "", err
					}
					return path, os.Mkdir(path, 0o700)
				},
				"fifo": func(path string) (string, error) {
					if err := os.Remove(path); err != nil {
						return "", err
					}
					return path, syscall.Mkfifo(path, 0o600)
				},
				// A device never ends: only the regular-file check stops
				// the read before it exhausts memory.
				"device": func(string) (string, error) { return "/dev/zero", nil },
			} {
				logs, gz := defaultLogs()
				f := newFixture(t, logs, gz)
				path, err := replace(*in.path(&f))
				if err != nil {
					t.Fatal(err)
				}
				*in.path(&f) = path
				done := make(chan error, 1)
				go func() { done <- run(f.args(), io.Discard, testEnv()) }()
				select {
				case err := <-done:
					if !errors.Is(err, in.want) {
						t.Fatalf("%s: %v, want %v", kind, err, in.want)
					}
				case <-time.After(10 * time.Second):
					t.Fatalf("%s: reading the input did not stop", kind)
				}
				if _, err := os.Lstat(f.manifest); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s: a refused input published a bundle", kind)
				}
			}
		})
	}

	logs, gz := defaultLogs()
	base := newFixture(t, logs, gz)
	// Each input's first member, and an optional member to set to null.
	for i, nullable := range []struct{ from, to string }{
		{`"trusted_proxies":["198.51.100.9"]`, `"trusted_proxies":null`},
		{`"episode":"e1"`, `"episode":null`},
	} {
		in := inputs[i]
		original := string(mustRead(t, *in.path(&base)))
		first := strings.Index(original, `"`)
		member := original[first : strings.Index(original[first+1:], `"`)+first+2]
		for kind, edit := range map[string]func(string) string{
			"duplicate member": func(s string) string { return strings.Replace(s, "{"+member+":", "{"+member+`: {}, `+member+":", 1) },
			"member case":      func(s string) string { return strings.Replace(s, member, strings.ToUpper(member), 1) },
			"null member":      func(s string) string { return strings.Replace(s, nullable.from, nullable.to, 1) },
			"trailing value":   func(s string) string { return s + " {}" },
		} {
			t.Run(in.name+"/"+kind, func(t *testing.T) {
				logs, gz := defaultLogs()
				f := newFixture(t, logs, gz)
				edited := edit(original)
				if edited == original {
					t.Fatal("edit did not change the input")
				}
				if err := os.WriteFile(*in.path(&f), []byte(edited), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := run(f.args(), io.Discard, testEnv()); !errors.Is(err, in.want) {
					t.Fatalf("%v, want %v", err, in.want)
				}
			})
		}
	}
}

// replacingFS swaps the registry lock file for a new one right after the
// conversion opens it, as a concurrent cleanup could.
type replacingFS struct{ osFS }

func (replacingFS) OpenFile(name string, flag int, perm os.FileMode) (file, error) {
	f, err := osFS{}.OpenFile(name, flag, perm)
	if err != nil || !strings.HasSuffix(name, ".lock") {
		return f, err
	}
	if err := errors.Join(os.Remove(name), os.WriteFile(name, nil, 0o600)); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func TestRegistryLockRecheckedAfterLocking(t *testing.T) {
	path := testRegistryPath(t.TempDir())
	fingerprint := saltFingerprint([]byte(strings.Repeat("B", 32)))
	if r, err := openRegistry(replacingFS{}, path, fingerprint); !errors.Is(err, errRegistry) {
		if r != nil {
			r.close()
		}
		t.Fatalf("lock replaced before locking: %v, want errRegistry", err)
	}
	r, err := openRegistry(osFS{}, path, fingerprint)
	if err != nil {
		t.Fatalf("an unreplaced lock must still work: %v", err)
	}
	r.close()
	if _, err := os.Lstat(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
}
