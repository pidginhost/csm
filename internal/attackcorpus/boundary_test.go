package attackcorpus

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLoadRejectsSymlinks(t *testing.T) {
	for _, entry := range []string{"category", "sample", "manifest", "content"} {
		t.Run(entry, func(t *testing.T) {
			root := t.TempDir()
			s := maliciousSample()
			dir := filepath.Join(root, s.Category, s.Name)
			writeSample(t, dir, s)
			paths := map[string]string{
				"category": filepath.Dir(dir),
				"sample":   dir,
				"manifest": filepath.Join(dir, "sample.json"),
				"content":  filepath.Join(dir, "a.b64"),
			}
			moveToSymlink(t, paths[entry], filepath.Join(t.TempDir(), "outside"))
			if _, err := Load(root, "private"); err == nil {
				t.Fatal("Load accepted a symlink outside the corpus")
			}
		})
	}
}

func TestContentRejectsReplacementSymlinks(t *testing.T) {
	for _, entry := range []string{"category", "sample", "content"} {
		t.Run(entry, func(t *testing.T) {
			root := t.TempDir()
			s := maliciousSample()
			dir := filepath.Join(root, s.Category, s.Name)
			writeSample(t, dir, s)
			samples, err := Load(root, "private")
			if err != nil || len(samples) != 1 {
				t.Fatalf("Load returned %d samples, error %v", len(samples), err)
			}
			paths := map[string]string{
				"category": filepath.Dir(dir),
				"sample":   dir,
				"content":  filepath.Join(dir, "a.b64"),
			}
			moveToSymlink(t, paths[entry], filepath.Join(t.TempDir(), "outside"))
			data, err := samples[0].Content(samples[0].Files[0])
			if err == nil || data != nil {
				t.Fatal("Content followed a replacement symlink or returned bytes on failure")
			}
		})
	}
}

func TestContentRejectsUnlistedFiles(t *testing.T) {
	root := t.TempDir()
	s := maliciousSample()
	dir := filepath.Join(root, s.Category, s.Name)
	writeSample(t, dir, s)
	samples, err := Load(root, "private")
	if err != nil || len(samples) != 1 {
		t.Fatalf("Load returned %d samples, error %v", len(samples), err)
	}
	for _, name := range []string{"../outside.b64", "bad.b64"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("b3V0c2lkZQ=="), 0o600); err != nil {
			t.Fatal(err)
		}
		f := samples[0].Files[0]
		f.B64 = name
		data, err := samples[0].Content(f)
		if err == nil || data != nil {
			t.Fatal("Content accepted an unlisted source or returned bytes on failure")
		}
	}
}

func TestContentKeepsLoadedLocation(t *testing.T) {
	t.Chdir(t.TempDir())
	s := maliciousSample()
	writeSample(t, filepath.Join("corpus", s.Category, s.Name), s)
	samples, err := Load("corpus", "private")
	if err != nil || len(samples) != 1 {
		t.Fatalf("Load returned %d samples, error %v", len(samples), err)
	}
	want, err := samples[0].Content(samples[0].Files[0])
	if err != nil || len(want) == 0 {
		t.Fatalf("initial Content failed: %v", err)
	}
	t.Chdir(t.TempDir())
	samples[0].Dir = t.TempDir()
	got, err := samples[0].Content(samples[0].Files[0])
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("changing cwd or Dir redirected Content")
	}
}

func TestContentRejectsDecodeFailureWithoutBytes(t *testing.T) {
	root := t.TempDir()
	s := maliciousSample()
	dir := filepath.Join(root, s.Category, s.Name)
	writeSample(t, dir, s)
	samples, err := Load(root, "private")
	if err != nil || len(samples) != 1 {
		t.Fatalf("Load returned %d samples, error %v", len(samples), err)
	}
	// A valid prefix makes the decoder return partial bytes alongside its error.
	if err = os.WriteFile(filepath.Join(dir, "a.b64"), []byte("aGFybWxlc3M=!"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := samples[0].Content(samples[0].Files[0])
	if err == nil || data != nil {
		t.Fatal("Content swallowed a decode error or returned partial bytes")
	}
}

func TestLoadRejectsNonRegularFiles(t *testing.T) {
	for _, name := range []string{"sample.json", "a.b64"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			s := maliciousSample()
			dir := filepath.Join(root, s.Category, s.Name)
			writeSample(t, dir, s)
			path := filepath.Join(dir, name)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(root, "private")
			wantErr(t, err, "regular file")
		})
	}
}

func TestLoadRejectsAmbiguousJSON(t *testing.T) {
	cases := []struct {
		name, from, to string
	}{
		{"duplicate kind", `"kind":"malicious"`, `"kind":"control","kind":"malicious"`},
		{"duplicate files", `"files":[`, `"files":[],"files":[`},
		{"duplicate file source", `"b64":"a.b64"`, `"b64":"bad.b64","b64":"a.b64"`},
		{"duplicate expectation", `"realtime":{`, `"realtime":{"gap":"lost expectation"},"realtime":{`},
		{"escaped duplicate", `"kind":"malicious"`, `"\u006bind":"control","kind":"malicious"`},
		{"case variant", `"kind":"malicious"`, `"Kind":"control","kind":"malicious"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := maliciousSample()
			manifest, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			changed := bytes.Replace(manifest, []byte(tc.from), []byte(tc.to), 1)
			if bytes.Equal(manifest, changed) {
				t.Fatal("test did not change the manifest")
			}
			root := t.TempDir()
			writeManifest(t, filepath.Join(root, s.Category, s.Name), changed)
			if _, err := Load(root, "private"); err == nil {
				t.Fatal("Load accepted an ambiguous manifest")
			}
		})
	}
}

func TestLoadRejectsConflictingFilePaths(t *testing.T) {
	for _, paths := range [][]string{
		{"public_html/a.php", "public_html/a.php/child"},
		{"public_html/a.php/child", "public_html/a.php"},
	} {
		s := controlSample()
		s.Files = nil
		for _, p := range paths {
			s.Files = append(s.Files, File{Path: p, B64: "a.b64"})
		}
		wantErr(t, loadOne(t, s), "conflicting paths")
	}
}

func TestLoadRejectsNULPath(t *testing.T) {
	s := controlSample()
	s.Files[0].Path = "public_html/a\x00.php"
	wantErr(t, loadOne(t, s), "unsafe path")
}

func TestLoadRejectsBlankGap(t *testing.T) {
	s := maliciousSample()
	s.Expect[Realtime] = PathExpect{Gap: " \n\t"}
	wantErr(t, loadOne(t, s), "findings or a gap")
}

func TestLoadJSONErrorsDoNotQuoteInput(t *testing.T) {
	const marker = "untrusted-manifest-text"
	for _, raw := range []string{
		`{"` + marker + `":true}`,
		`{"mode":` + marker + `}`,
		`{"files":[{"mode":"` + marker + `"}]}`,
	} {
		root := t.TempDir()
		writeManifest(t, filepath.Join(root, "webshell", caseName), []byte(raw))
		_, err := Load(root, "private")
		if err == nil {
			t.Fatal("Load accepted invalid JSON fields")
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatal("JSON error quoted manifest input")
		}
	}
}

func moveToSymlink(t *testing.T, path, target string) {
	t.Helper()
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}
