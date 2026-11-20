package webserver

import (
	"bytes"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

type peerDirectoryInfo struct {
	os.FileInfo
	uid, gid uint32
}

func (s peerDirectoryInfo) Sys() any {
	st := *s.FileInfo.Sys().(*syscall.Stat_t)
	st.Uid, st.Gid = s.uid, s.gid
	return &st
}

// Repair must take ownership before admitting any group, including when the
// mode is already correct. Otherwise the old owner can reopen or replace logs.
func TestPeerLogDirectoryOwnership(t *testing.T) {
	group, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, group string
		uid, gid    uint32
		wantGID     int
	}{
		{"cpanel owner", group.Name, 12345, uint32(os.Getgid()), os.Getgid()},
		{"cpanel group", group.Name, 0, 12345, os.Getgid()},
		{"apache owner", "", 12345, 0, 0},
		{"apache group", "", 0, 12345, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &fakeHandler{kind: "apache"}
			i := newPeerLogInstaller(t, h)
			i.PeerLogGroup = tc.group
			if err := os.MkdirAll(i.PeerLogDir, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(i.PeerLogPath), 0o755); err != nil {
				t.Fatal(err)
			}
			original := []byte(templateHeaderPrefix + "99\n# retained\n")
			if err := os.WriteFile(i.PeerLogPath, original, 0o644); err != nil {
				t.Fatal(err)
			}
			i.LstatAt = func(path string) (os.FileInfo, error) {
				info, err := os.Lstat(path)
				if err != nil {
					return nil, err
				}
				return peerDirectoryInfo{info, tc.uid, tc.gid}, nil
			}
			chowns := 0
			i.ChownAt = func(path string, uid, gid int) error {
				chowns++
				if path != i.PeerLogDir || uid != 0 || gid != tc.wantGID {
					t.Errorf("chown(%s, %d, %d), want log directory, 0, %d", path, uid, gid, tc.wantGID)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0o700 {
					t.Errorf("directory exposed to old group during repair: %04o", info.Mode().Perm())
				}
				return nil
			}
			res, err := i.InstallPeerLog()
			if err != nil || res.Status != "ok" {
				t.Fatalf("install = %+v, %v", res, err)
			}
			if chowns != 1 || h.validates.Load() != 1 || h.reloads.Load() != 1 {
				t.Errorf("chown/validate/reload = %d/%d/%d, want 1/1/1", chowns, h.validates.Load(), h.reloads.Load())
			}
			info, err := os.Stat(i.PeerLogDir)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o750 {
				t.Errorf("mode = %04o", info.Mode().Perm())
			}
			got, err := os.ReadFile(i.PeerLogPath)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatalf("newer snippet changed: %q, %v", got, err)
			}
		})
	}
}

func TestPeerLogDirectoryRejectsSymlink(t *testing.T) {
	h := &fakeHandler{kind: "apache"}
	i := newPeerLogInstaller(t, h)
	target := t.TempDir()
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(i.PeerLogDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, i.PeerLogDir); err != nil {
		t.Fatal(err)
	}
	if res, err := i.InstallPeerLog(); err == nil || res.Status != "fail" {
		t.Errorf("symlink accepted: %+v, %v", res, err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("symlink target permissions changed: %04o", info.Mode().Perm())
	}
	if _, err := os.Stat(i.PeerLogPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("snippet written: %v", err)
	}
	if h.validates.Load() != 0 || h.reloads.Load() != 0 {
		t.Fatal("web server touched after unsafe directory")
	}
}

func TestPeerLogUpgradesPreviousLogLocation(t *testing.T) {
	h := &fakeHandler{kind: "apache"}
	i := newPeerLogInstaller(t, h)
	body, renderErr := i.peerLogBody()
	if renderErr != nil {
		t.Fatal(renderErr)
	}
	old := strings.ReplaceAll(string(body), i.PeerLogDir, "/var/log/csm")
	old = strings.ReplaceAll(old, "/peer.log", "/web-peer.log")
	old = strings.Replace(old, templateHeaderPrefix+strconv.Itoa(PeerLogTemplateVersion), templateHeaderPrefix+"2", 1)
	if err := os.MkdirAll(filepath.Dir(i.PeerLogPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(i.PeerLogPath, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	if res, err := i.PeerLogStatus(); err != nil || res.Status != "stale" {
		t.Errorf("old location status = %+v, %v", res, err)
	}
	if res, err := i.InstallPeerLog(); err != nil || res.Status != "ok" {
		t.Fatalf("upgrade = %+v, %v", res, err)
	}
	got, err := os.ReadFile(i.PeerLogPath)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("old log location retained: %q, %v", got, err)
	}
	if h.validates.Load() != 1 || h.reloads.Load() != 1 {
		t.Fatal("new location not activated")
	}
}

// An optional sandbox grant is only mounted when the daemon starts. The
// operator must restart it after installing a directory that was absent.
func TestPeerLogInstallReportsDaemonRestart(t *testing.T) {
	i := newPeerLogInstaller(t, &fakeHandler{kind: "apache"})
	for _, want := range []string{"ok", "no-op"} {
		res, err := i.InstallPeerLog()
		if err != nil || res.Status != want || !strings.Contains(res.Message, "systemctl restart csm.service") {
			t.Fatalf("install = %+v, %v; want %s with restart instruction", res, err, want)
		}
	}
}

// Failed permission repair must not expose the old group or publish a snippet.
func TestPeerLogDirectoryRepairFailure(t *testing.T) {
	for _, stage := range []string{"stat", "mkdir", "close access", "chown", "open access"} {
		t.Run(stage, func(t *testing.T) {
			h := &fakeHandler{kind: "apache"}
			i := newPeerLogInstaller(t, h)
			if err := os.MkdirAll(i.PeerLogDir, 0o700); err != nil {
				t.Fatal(err)
			}
			failure := errors.New("permission repair failed")
			switch stage {
			case "stat":
				i.LstatAt = func(string) (os.FileInfo, error) { return nil, failure }
			case "mkdir":
				i.MkdirAll = func(string, os.FileMode) error { return failure }
			case "chown":
				i.ChownAt = func(string, int, int) error { return failure }
			default:
				i.ChmodAt = func(path string, mode os.FileMode) error {
					if (stage == "close access" && mode == 0o700) || (stage == "open access" && mode == 0o750) {
						return failure
					}
					return os.Chmod(path, mode)
				}
			}
			if res, err := i.InstallPeerLog(); !errors.Is(err, failure) || res.Status != "fail" {
				t.Fatalf("failure lost: %+v, %v", res, err)
			}
			info, err := os.Stat(i.PeerLogDir)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o700 {
				t.Errorf("failed repair exposed directory: %04o", info.Mode().Perm())
			}
			if _, err := os.Stat(i.PeerLogPath); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("snippet written: %v", err)
			}
			if h.validates.Load() != 0 || h.reloads.Load() != 0 {
				t.Fatal("web server touched after failed directory repair")
			}
		})
	}
}
