package hostfacts

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

func mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// after returns the part of dirs that starts at d.
func after(t *testing.T, dirs []string, d string) []string {
	t.Helper()
	i := slices.Index(dirs, d)
	if i < 0 {
		t.Fatalf("%s not walked: %v", d, dirs)
	}
	return dirs[i:]
}

// EL8's /var/run is a relative symlink to ../run. The walk must report /var,
// where the link lives, and the real directories it leads to.
func TestResolveRecordsSymlinkDirectories(t *testing.T) {
	d := t.TempDir()
	mkdir(t, filepath.Join(d, "run", "rspamd"))
	mkdir(t, filepath.Join(d, "var"))
	symlink(t, "../run", filepath.Join(d, "var", "run"))
	write(t, filepath.Join(d, "run", "rspamd", "s"), "")

	final, dirs, err := resolve(filepath.Join(d, "var", "run", "rspamd", "s"))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(d, "run", "rspamd", "s"); final != want {
		t.Errorf("final = %s, want %s", final, want)
	}
	want := []string{d, filepath.Join(d, "var"), filepath.Join(d, "run"), filepath.Join(d, "run", "rspamd")}
	if got := after(t, dirs, d); !slices.Equal(got, want) {
		t.Errorf("dirs = %v, want %v", got, want)
	}
	if dirs[0] != "/" {
		t.Errorf("walk starts at %s, want /", dirs[0])
	}
}

func TestResolveFollowsAbsoluteLinksAndFinalLink(t *testing.T) {
	d := t.TempDir()
	mkdir(t, filepath.Join(d, "real"))
	mkdir(t, filepath.Join(d, "links"))
	write(t, filepath.Join(d, "real", "s"), "")
	symlink(t, filepath.Join(d, "real", "s"), filepath.Join(d, "links", "s"))

	final, dirs, err := resolve(filepath.Join(d, "links", "s"))
	if err != nil || final != filepath.Join(d, "real", "s") {
		t.Fatalf("final = %s, err = %v", final, err)
	}
	if !slices.Contains(dirs, filepath.Join(d, "links")) || !slices.Contains(dirs, filepath.Join(d, "real")) {
		t.Errorf("dirs %v miss the link's or the target's directory", dirs)
	}
}

func TestResolveFailures(t *testing.T) {
	d := t.TempDir()
	symlink(t, "loop", filepath.Join(d, "loop"))
	write(t, filepath.Join(d, "file"), "")

	if _, _, err := resolve(filepath.Join(d, "missing", "s")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing directory: err = %v, want not exist", err)
	}
	if _, _, err := resolve(filepath.Join(d, "loop", "s")); err == nil {
		t.Error("symlink loop resolved")
	}
	if _, _, err := resolve(filepath.Join(d, "file", "s")); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("file as directory: err = %v, want a non-absence error", err)
	}
}

func TestChainStopsAtSymlink(t *testing.T) {
	d := t.TempDir()
	mkdir(t, filepath.Join(d, "real", "sub"))
	symlink(t, "real", filepath.Join(d, "link"))

	got, err := chain(filepath.Join(d, "link", "sub"))
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if last.Path != filepath.Join(d, "link") || last.Mode&fs.ModeSymlink == 0 {
		t.Fatalf("chain ends at %+v, want the symlink", last)
	}
	if got[0].Path != "/" || !got[0].Mode.IsDir() {
		t.Errorf("chain starts at %+v, want /", got[0])
	}
	if _, err := chain(filepath.Join(d, "missing", "sub")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing directory: err = %v, want not exist", err)
	}
}

func TestPathFactsReportsOwnerAndMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	write(t, p, "x")
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	got, err := pathFacts(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != p || got.UID != os.Getuid() || got.GID != os.Getgid() || got.Mode != 0o640 || got.ExtACL {
		t.Fatalf("got %+v", got)
	}
}

func TestTargetFacts(t *testing.T) {
	d := t.TempDir()
	mkdir(t, filepath.Join(d, "local.d"))
	write(t, filepath.Join(d, "local.d", "actions.conf"), antispam.ManagedHeader+"\n")
	symlink(t, "actions.conf", filepath.Join(d, "local.d", "link.conf"))
	symlink(t, "local.d", filepath.Join(d, "linkdir"))

	present := targetFacts(antispam.Target{Path: filepath.Join(d, "local.d", "actions.conf"), Kind: antispam.TargetRspamd})
	if present.Err != nil || present.Missing || !present.File.Mode.IsRegular() || present.Content != "" {
		t.Errorf("present file: %+v", present)
	}
	absent := targetFacts(antispam.Target{Path: filepath.Join(d, "local.d", "rbl.conf"), Kind: antispam.TargetRspamd})
	if absent.Err != nil || !absent.Missing || len(absent.Parents) == 0 {
		t.Errorf("absent file: %+v", absent)
	}
	link := targetFacts(antispam.Target{Path: filepath.Join(d, "local.d", "link.conf"), Kind: antispam.TargetRspamd})
	if link.File.Mode&fs.ModeSymlink == 0 || link.Content != "" {
		t.Errorf("symlinked file was followed: %+v", link)
	}
	under := targetFacts(antispam.Target{Path: filepath.Join(d, "linkdir", "actions.conf"), Kind: antispam.TargetRspamd})
	if last := under.Parents[len(under.Parents)-1]; last.Mode&fs.ModeSymlink == 0 || under.File.Mode != 0 || under.Content != "" {
		t.Errorf("file under a symlinked directory was read: %+v", under)
	}
	noDir := targetFacts(antispam.Target{Path: filepath.Join(d, "nodir", "x.conf"), Kind: antispam.TargetRspamd})
	if !errors.Is(noDir.Err, fs.ErrNotExist) || noDir.Missing {
		t.Errorf("missing directory: %+v", noDir)
	}
}

func TestTargetFactsDoesNotReadUnsafePaths(t *testing.T) {
	d := t.TempDir()
	for _, mode := range []fs.FileMode{0o644, 0o666} {
		p := filepath.Join(d, "unsafe.conf")
		write(t, p, antispam.ManagedHeader+"\n")
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		got := targetFacts(antispam.Target{Path: p, Kind: antispam.TargetRspamd})
		if got.Err != nil || got.Missing || !got.File.Mode.IsRegular() || got.Content != "" {
			t.Errorf("unsafe path was read: %+v", got)
		}
	}
}

func TestReadRegularContent(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "file")
	write(t, p, antispam.ManagedHeader+"\n")
	got, err := readRegularContent(p, maxConfigBytes)
	if err != nil || got != antispam.ManagedHeader+"\n" {
		t.Fatalf("regular file: got=%q err=%v", got, err)
	}
	symlink(t, "file", filepath.Join(d, "link"))
	if got, err := readRegularContent(filepath.Join(d, "link"), maxConfigBytes); err == nil || got != "" {
		t.Errorf("symlink read: got=%q err=%v", got, err)
	}
	mkdir(t, filepath.Join(d, "dir"))
	if got, err := readRegularContent(filepath.Join(d, "dir"), maxConfigBytes); err == nil || got != "" {
		t.Errorf("directory read: got=%q err=%v", got, err)
	}
	symlink(t, ".", filepath.Join(d, "linkdir"))
	if got, err := readRegularContent(filepath.Join(d, "linkdir", "file"), maxConfigBytes); err == nil || got != "" {
		t.Errorf("symlinked parent read: got=%q err=%v", got, err)
	}
}

func TestTargetSafeToRead(t *testing.T) {
	good := func() antispam.TargetFacts {
		return antispam.TargetFacts{
			File: antispam.PathFacts{Mode: 0o644},
			Parents: []antispam.PathFacts{
				{Path: "/", Mode: fs.ModeDir | 0o755},
				{Path: "/etc", Mode: fs.ModeDir | 0o755},
			},
		}
	}
	if !targetSafeToRead(good()) {
		t.Fatal("protected target refused")
	}
	for name, mutate := range map[string]func(*antispam.TargetFacts){
		"file owner":         func(f *antispam.TargetFacts) { f.File.UID = 1000 },
		"file group write":   func(f *antispam.TargetFacts) { f.File.Mode |= 0o020 },
		"file other write":   func(f *antispam.TargetFacts) { f.File.Mode |= 0o002 },
		"file ACL":           func(f *antispam.TargetFacts) { f.File.ExtACL = true },
		"file symlink":       func(f *antispam.TargetFacts) { f.File.Mode |= fs.ModeSymlink },
		"ancestor owner":     func(f *antispam.TargetFacts) { f.Parents[0].UID = 1000 },
		"parent group write": func(f *antispam.TargetFacts) { f.Parents[1].Mode |= 0o020 },
		"parent other write": func(f *antispam.TargetFacts) { f.Parents[1].Mode |= 0o002 },
		"parent ACL":         func(f *antispam.TargetFacts) { f.Parents[1].ExtACL = true },
		"parent symlink":     func(f *antispam.TargetFacts) { f.Parents[1].Mode = fs.ModeSymlink | 0o755 },
	} {
		t.Run(name, func(t *testing.T) {
			f := good()
			mutate(&f)
			if targetSafeToRead(f) {
				t.Fatal("unsafe target accepted for reading")
			}
		})
	}
}

func TestResolveRequiresDirectoryForTrailingSlash(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "file"), "")
	mkdir(t, filepath.Join(d, "dir"))
	symlink(t, "file/", filepath.Join(d, "bad"))
	symlink(t, "dir/", filepath.Join(d, "good"))
	for _, p := range []string{filepath.Join(d, "bad"), filepath.Join(d, "file") + "/"} {
		if _, err := os.Stat(p); !errors.Is(err, syscall.ENOTDIR) {
			t.Fatalf("kernel lookup of %s: %v, want ENOTDIR", p, err)
		}
		if _, _, err := resolve(p); !errors.Is(err, syscall.ENOTDIR) {
			t.Errorf("resolve(%s) = %v, want ENOTDIR", p, err)
		}
	}
	if final, _, err := resolve(filepath.Join(d, "good")); err != nil || final != filepath.Join(d, "dir") {
		t.Errorf("directory with trailing slash: final=%s err=%v", final, err)
	}
}

func TestTargetsKeepsOrder(t *testing.T) {
	d := t.TempDir()
	in := []antispam.Target{
		{Path: filepath.Join(d, "b.conf"), Kind: antispam.TargetRspamd},
		{Path: filepath.Join(d, "a.conf"), Kind: antispam.TargetEximHook},
	}
	got := Targets(in)
	if len(got) != 2 || got[0].Target != in[0] || got[1].Target != in[1] || !got[0].Missing {
		t.Errorf("Targets = %+v", got)
	}
}
