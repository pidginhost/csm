package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func compressRestoreFixture(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestRestoreValidatesCompleteCompressedStream(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "valid.tar.gz")
	entries := []archiveTestEntry{{name: "csm.yaml", size: 3, body: []byte("new")}, {name: "conf.d/new.yaml", size: 3, body: []byte("new")}, {name: "state/new", size: 3, body: []byte("new")}}
	if err := writeArchiveEntries(original, entries); err != nil {
		t.Fatal(err)
	}
	valid, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	crc := bytes.Clone(valid)
	crc[len(crc)-8] ^= 1
	size := bytes.Clone(valid)
	size[len(size)-4] ^= 1
	cases := []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"valid", valid, true},
		{"CRC", crc, false},
		{"size", size, false},
		{"truncated compressed payload", valid[:len(valid)/2], false},
		{"truncated tar payload", compressRestoreFixture(t, plain[:513]), false},
		{"raw trailing data", append(bytes.Clone(valid), 'x'), false},
		{"raw trailing zero", append(bytes.Clone(valid), 0), false},
		{"second gzip member", append(bytes.Clone(valid), valid...), false},
		{"empty second gzip member", append(bytes.Clone(valid), compressRestoreFixture(t, nil)...), false},
		{"data after tar EOF", compressRestoreFixture(t, append(bytes.Clone(plain), 'x')), false},
		{"padding after tar EOF", compressRestoreFixture(t, append(bytes.Clone(plain), make([]byte, 512)...)), false},
	}
	for n := 1; n <= 8; n++ {
		cases = append(cases, struct {
			name  string
			data  []byte
			valid bool
		}{fmt.Sprintf("trailer missing %d bytes", n), valid[:len(valid)-n], false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dst := BackupSources{ConfigPath: filepath.Join(root, "csm.yaml"), ConfDir: filepath.Join(root, "conf.d"), StateDir: filepath.Join(root, "state")}
			for _, path := range []string{dst.ConfDir, dst.StateDir} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			originals := []string{dst.ConfigPath, filepath.Join(dst.ConfDir, "old.yaml"), filepath.Join(dst.StateDir, "old")}
			for _, path := range originals {
				if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			archive := filepath.Join(t.TempDir(), "backup.tar.gz")
			if err := os.WriteFile(archive, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			err := RestoreBackupArchive(archive, dst)
			if tc.valid {
				if err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{dst.ConfigPath, filepath.Join(dst.ConfDir, "new.yaml"), filepath.Join(dst.StateDir, "new")} {
					data, readErr := os.ReadFile(path)
					if readErr != nil || string(data) != "new" {
						t.Fatalf("valid restore %s=%q, error=%v", path, data, readErr)
					}
				}
				return
			}
			if err == nil {
				t.Error("invalid compressed stream accepted")
			}
			for _, path := range originals {
				data, readErr := os.ReadFile(path)
				if readErr != nil || string(data) != "original" {
					t.Errorf("invalid archive changed %s: %q, error=%v", path, data, readErr)
				}
			}
			for _, path := range []string{filepath.Join(dst.ConfDir, "new.yaml"), filepath.Join(dst.StateDir, "new")} {
				if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
					t.Errorf("invalid archive created %s: %v", path, statErr)
				}
			}
			staged, globErr := filepath.Glob(filepath.Join(root, ".csm-restore-*"))
			if globErr != nil || len(staged) != 0 {
				t.Errorf("failed restore leaked staging: %v, error=%v", staged, globErr)
			}
		})
	}
}
