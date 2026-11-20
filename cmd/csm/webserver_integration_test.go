package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integration/webserver"
)

func TestWebserverIntegrationConfigFailureStillInstallsPeerLog(t *testing.T) {
	for _, verb := range []string{"install", "upgrade"} {
		t.Run(verb, func(t *testing.T) {
			root := t.TempDir()
			h := &fakeWebserverHandler{snippet: filepath.Join(root, "challenge.conf")}
			inst := &webserver.Installer{
				Handler:  h,
				ReadAt:   os.ReadFile,
				WriteAt:  os.WriteFile,
				RemoveAt: os.Remove,
				StatAt:   os.Stat,
				LstatAt:  os.Lstat,
				MkdirAll: os.MkdirAll,
				ChmodAt:  os.Chmod,
				ChownAt: func(path string, uid, gid int) error {
					if path != filepath.Join(root, "logs") || uid != 0 || gid != 0 {
						t.Errorf("unexpected directory ownership: %s %d:%d", path, uid, gid)
					}
					return nil
				},
				Stderr:      io.Discard,
				PeerLogPath: filepath.Join(root, "peer.conf"),
				PeerLogDir:  filepath.Join(root, "logs"),
			}
			failure := errors.New("config unavailable")
			res, err := runWebserverIntegrationWithConfig(inst, verb, func() (*config.Config, error) { return nil, failure })
			if !errors.Is(err, failure) || res.Status != "fail" || res.Message != failure.Error() {
				t.Fatalf("configuration failure lost: %+v, %v", res, err)
			}
			if res.PeerLog == nil || res.PeerLog.Status != "ok" {
				t.Fatalf("peer log not installed: %+v", res.PeerLog)
			}
			if _, err := os.Stat(inst.PeerLogPath); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(h.snippet); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("challenge installed without its config: %v", err)
			}
		})
	}
}
