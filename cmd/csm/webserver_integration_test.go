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
	} {
		verb, peerLog, asJSON, ok := parseWebserverIntegrationArgs(tc.args)
		if ok != tc.ok || ok && (verb != tc.verb || peerLog != tc.peerLog || asJSON != tc.json) {
			t.Errorf("parse(%q) = %q %v %v %v, want %q %v %v %v", tc.args, verb, peerLog, asJSON, ok, tc.verb, tc.peerLog, tc.json, tc.ok)
		}
	}
}
