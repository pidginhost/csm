package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// --- CheckWebshells with SUID + dangerous patterns -------------------

func TestCheckWebshellsDeep(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "alice") && !strings.Contains(name, "public_html") {
				return []os.DirEntry{testDirEntry{name: "public_html", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{
					testDirEntry{name: "shell.php", isDir: false},
					testDirEntry{name: "normal.html", isDir: false},
					testDirEntry{name: "uploads", isDir: true},
				}, nil
			}
			if strings.Contains(name, "uploads") {
				return []os.DirEntry{
					testDirEntry{name: "backdoor.php", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "shell.php") {
				return []byte("<?php system($_GET['cmd']); ?>"), nil
			}
			if strings.HasSuffix(name, "backdoor.php") {
				return []byte("<?php passthru($_POST['x']); ?>"), nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "test", size: 500}, nil
		},
		lstat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "test", size: 500}, nil
		},
	})

	_ = CheckWebshells(context.Background(), &config.Config{}, nil)
}

// --- CheckFilesystem with tmp/shm files ------------------------------

func TestCheckFilesystemDeep(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "/tmp") {
				return []string{"/tmp/.hidden_miner"}, nil
			}
			if strings.Contains(pattern, "/dev/shm") {
				return []string{"/dev/shm/.x"}, nil
			}
			return nil, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "test", size: 100}, nil
		},
		lstat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "test", size: 100}, nil
		},
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return nil, nil
			}
			return nil, os.ErrNotExist
		},
	})

	_ = CheckFilesystem(context.Background(), &config.Config{}, nil)
}

// --- CheckOutdatedPlugins with wp-cli output -------------------------

func TestCheckOutdatedPluginsDeep(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "wp" {
				return []byte(`[{"name":"elementor","status":"active","version":"3.0.0","update_version":"3.5.0"}]`), nil
			}
			return nil, nil
		},
	})

	_ = CheckOutdatedPlugins(context.Background(), &config.Config{}, nil)
}

// --- CheckErrorLogBloat with large logs ------------------------------

func TestCheckErrorLogBloatDeep(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{
					testDirEntry{name: "error_log", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if strings.HasSuffix(name, "error_log") {
				return fakeFileInfo{name: "error_log", size: 200 * 1024 * 1024}, nil
			}
			return fakeFileInfo{name: "test", size: 0}, nil
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	_ = CheckErrorLogBloat(context.Background(), &config.Config{}, store)
}

// --- CheckWPConfig with insecure settings ----------------------------

func TestCheckWPConfigInsecure(t *testing.T) {
	wpConfig := "<?php\ndefine('WP_DEBUG', true);\ndefine('WP_MEMORY_LIMIT', '40M');\ndefine('WP_DEBUG_DISPLAY', true);\ndefine('DB_NAME','wp');\ndefine('DB_USER','u');\ndefine('DB_PASSWORD','p');\ndefine('DB_HOST','localhost');\n"

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{testDirEntry{name: "wp-config.php", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				return []byte(wpConfig), nil
			}
			return nil, os.ErrNotExist
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	_ = CheckWPConfig(context.Background(), &config.Config{}, store)
}

// --- InlineQuarantine with real temp file -----------------------------

func TestInlineQuarantineWithRealFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/malware.php"
	_ = os.WriteFile(path, []byte("<?php system('id'); ?>"), 0644)

	old := osFS
	osFS = realOS{}
	defer func() { osFS = old }()

	f := alert.Finding{Check: "webshell", FilePath: path}
	_, ok := InlineQuarantine(f, path, []byte("<?php system('id'); ?>"))
	_ = ok // exercises the quarantine path
}
