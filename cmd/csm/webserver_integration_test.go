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

// A configuration failure fails install and upgrade and leaves the peer log,
// which has its own verbs, alone (operator ruling 2026-11-21).
func TestWebserverIntegrationConfigFailureLeavesPeerLog(t *testing.T) {
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
					t.Errorf("unexpected directory change: %s %d:%d", path, uid, gid)
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
			if res.PeerLog != nil {
				t.Fatalf("%s touched the peer log: %+v", verb, res.PeerLog)
			}
			if _, err := os.Stat(inst.PeerLogPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s installed the peer log: %v", verb, err)
			}
			if _, err := os.Stat(h.snippet); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("challenge installed without its config: %v", err)
			}
		})
	}
}

// The peer log verbs parse as their own group; anything else stays a
// challenge verb.
func TestParseWebserverIntegrationArgs(t *testing.T) {
	for _, tc := range []struct {
		args          []string
		verb          string
		peerLog, json bool
		ok            bool
	}{
		{[]string{"install"}, "install", false, false, true},
		{[]string{"peer-log", "install", "--json"}, "install", true, true, true},
		{[]string{"--json", "peer-log", "status"}, "status", true, true, true},
		{[]string{"peer-log", "remove"}, "remove", true, false, true},
		{[]string{"peer-log", "upgrade"}, "", false, false, false},
		{[]string{"peer-log"}, "", false, false, false},
		{[]string{"bogus"}, "", false, false, false},
		// The configuration flags every csm command reads stay accepted.
		{[]string{"install", "--config", "/etc/csm/csm.yaml"}, "install", false, false, true},
		{[]string{"--config=/etc/csm/csm.yaml", "peer-log", "status"}, "status", true, false, true},
		{[]string{"upgrade", "--config-dir", "/etc/csm/conf.d", "--json"}, "upgrade", false, true, true},
		{[]string{"install", "--config"}, "", false, false, false},
		{[]string{"peer-log", "remove", "--config", "--dry-run"}, "", false, false, false},
		{[]string{"peer-log", "install", "--config-dir", "--bogus"}, "", false, false, false},
		{[]string{"install", "--config", "--json"}, "", false, false, false},
		{[]string{"install", "--config", ""}, "", false, false, false},
		{[]string{"install", "--config-dir", ""}, "", false, false, false},
		{[]string{"install", "--config="}, "", false, false, false},
		{[]string{"peer-log", "remove", "--config-dir="}, "", false, false, false},
		{[]string{"install", "--bogus"}, "", false, false, false},
		{[]string{"peer-log", "remove", "--dry-run"}, "", false, false, false},
		{[]string{"peer-log", "install", "remove"}, "", false, false, false},
		{[]string{"remove", "peer-log"}, "", false, false, false},
	} {
		verb, peerLog, asJSON, ok := parseWebserverIntegrationArgs(tc.args)
		if ok != tc.ok || ok && (verb != tc.verb || peerLog != tc.peerLog || asJSON != tc.json) {
			t.Errorf("parse(%q) = %q %v %v %v, want %q %v %v %v", tc.args, verb, peerLog, asJSON, ok, tc.verb, tc.peerLog, tc.json, tc.ok)
		}
	}
}

func TestWebserverIntegrationConfigOverridesReachLoader(t *testing.T) {
	for _, equals := range []bool{false, true} {
		args := []string{"csm", "webserver-integration", "install"}
		cfgPath, confDir := "/etc/csm/custom.yaml", "/etc/csm/custom.d"
		if equals {
			args = append(args, "--config="+cfgPath, "--config-dir="+confDir)
		} else {
			args = append(args, "--config", cfgPath, "--config-dir", confDir)
		}
		if _, _, _, ok := parseWebserverIntegrationArgs(args[2:]); !ok {
			t.Fatalf("rejected valid configuration overrides: %q", args)
		}
		if got, explicit := configPathFromArgs(args); !explicit || got != cfgPath {
			t.Errorf("config path for %q = %q, explicit=%v; want %q", args, got, explicit, cfgPath)
		}
		if got, explicit, err := configDirFromArgs(args); err != nil || !explicit || got != confDir {
			t.Errorf("config dir for %q = %q, explicit=%v, err=%v; want %q", args, got, explicit, err, confDir)
		}
	}
}
