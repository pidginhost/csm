package attackcorpus

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

// loaded writes s as a one-sample corpus, plus any extra files beside its
// manifest, and returns it as Load reads it: only loaded samples have content.
func loaded(t *testing.T, s Sample, extra map[string]string) Sample {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, s.Category, s.Name)
	writeSample(t, dir, s)
	for name, content := range extra {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	samples, err := Load(root, "public")
	if err != nil || len(samples) != 1 {
		t.Fatalf("Load returned %d samples, error %v", len(samples), err)
	}
	return samples[0]
}

// controlWith is a loadable control sample with the given files.
func controlWith(files ...File) Sample {
	s := controlSample()
	s.Files = files
	return s
}

func TestPlantWritesUnderAccount(t *testing.T) {
	s := loaded(t, controlWith(
		File{Path: "public_html/a.php", B64: "a.b64"},
		File{Path: "public_html/wp-content/uploads/b.php", B64: "a.b64", Mode: 0o666},
		File{Path: ".cache/c", B64: "a.b64", Mode: 0o600},
		File{Path: "@crontab", B64: "a.b64"},
	), nil)
	root := t.TempDir()
	cronDir := filepath.Join(t.TempDir(), "spool", "cron")
	// A umask this strict would narrow every mode Plant does not set itself.
	old := unix.Umask(0o077)
	t.Cleanup(func() { unix.Umask(old) })

	planted, err := s.Plant(root, cronDir, "acct")
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}
	home := filepath.Join(root, "acct")
	want := map[string]string{
		"public_html/a.php":                    filepath.Join(home, "public_html", "a.php"),
		"public_html/wp-content/uploads/b.php": filepath.Join(home, "public_html", "wp-content", "uploads", "b.php"),
		".cache/c":                             filepath.Join(home, ".cache", "c"),
		"@crontab":                             filepath.Join(cronDir, "acct"),
	}
	if !reflect.DeepEqual(planted, want) {
		t.Fatalf("planted = %v\nwant %v", planted, want)
	}

	modes := map[string]os.FileMode{"public_html/a.php": 0o644, "public_html/wp-content/uploads/b.php": 0o666, ".cache/c": 0o600, "@crontab": 0o644}
	for p, abs := range planted {
		info, err := os.Lstat(abs)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != modes[p] {
			t.Errorf("%s: mode %v, want regular %v", p, info.Mode(), modes[p])
		}
		// #nosec G304 -- abs is a file this test planted under t.TempDir().
		data, err := os.ReadFile(abs)
		if err != nil || string(data) != "harmless test text\n" {
			t.Errorf("%s: content %q, %v", p, data, err)
		}
		if got := Attribute(abs, root, cronDir, "acct"); got != p {
			t.Errorf("Attribute(%s) = %q, want %q", abs, got, p)
		}
	}
	for _, dir := range []string{home, filepath.Join(home, "public_html"), filepath.Join(home, "public_html", "wp-content"), filepath.Join(home, "public_html", "wp-content", "uploads"), filepath.Join(home, ".cache")} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Errorf("dir %s: mode %v, want 0755", dir, info.Mode().Perm())
		}
	}

	for _, abs := range []string{
		"",
		home,
		filepath.Join(root, "other", "public_html", "a.php"),
		filepath.Join(cronDir, "other"),
		filepath.Join(root, "acct2", "a.php"),
		"/etc/passwd",
	} {
		if got := Attribute(abs, root, cronDir, "acct"); got != "" {
			t.Errorf("Attribute(%q) = %q, want unattributed", abs, got)
		}
	}
	if got := Attribute(filepath.Join(home, "public_html"), root, cronDir, "acct"); got != "public_html" {
		t.Errorf("Attribute(planted dir) = %q, want public_html", got)
	}
}

func TestPlantRefusesSymlinks(t *testing.T) {
	s := loaded(t, controlSample(), nil)
	// The same sample plants into a clean tree, so the refusals below come
	// from the symlinks and not from the sample.
	if _, err := s.Plant(t.TempDir(), t.TempDir(), "acct"); err != nil {
		t.Fatalf("Plant into a clean tree: %v", err)
	}

	t.Run("file", func(t *testing.T) {
		root := t.TempDir()
		outside := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(outside, []byte("keep\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(root, "acct", "public_html"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "acct", "public_html", "a.php")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Plant(root, t.TempDir(), "acct"); err == nil {
			t.Fatal("Plant wrote through a symlinked file")
		}
		// #nosec G304 -- outside is a file this test created under t.TempDir().
		if data, err := os.ReadFile(outside); err != nil || string(data) != "keep\n" {
			t.Errorf("symlink target = %q, %v; want it unchanged", data, err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "acct"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "acct", "public_html")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Plant(root, t.TempDir(), "acct"); err == nil {
			t.Fatal("Plant wrote through a symlinked directory")
		}
		if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
			t.Errorf("symlinked directory holds %v, %v; want it empty", entries, err)
		}
	})
}

func TestPlantReturnsAbsolutePaths(t *testing.T) {
	s := loaded(t, controlWith(
		File{Path: fileA, B64: "a.b64"},
		File{Path: "@crontab", B64: "a.b64"},
	), nil)
	t.Chdir(t.TempDir())
	planted, err := s.Plant("homes", "cron", "acct")
	if err != nil {
		t.Fatal(err)
	}
	for path, relative := range map[string]string{fileA: "homes/acct/" + fileA, "@crontab": "cron/acct"} {
		want, err := filepath.Abs(relative)
		if err != nil {
			t.Fatal(err)
		}
		if planted[path] != want {
			t.Errorf("planted %s at %q, want absolute path %q", path, planted[path], want)
		}
		if got := Attribute(planted[path], "homes", "cron", "acct"); got != path {
			t.Errorf("attributed %s as %q with relative roots", path, got)
		}
	}
}
