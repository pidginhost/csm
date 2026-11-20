package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integration/webserver"
)

func uninstallRecorder(events *[]string, removeIntegration func() error) *Installer {
	return &Installer{
		BinaryPath:  "/opt/csm/csm",
		CommandPath: "/usr/sbin/csm",
		ConfigPath:  "/etc/csm/csm.yaml",
		StatePath:   "/var/lib/csm/state",
		LogPath:     "/var/log/csm/monitor.log",
		operations: &installerOperations{
			getuid:                     func() int { return 0 },
			runCommand:                 func(string, ...string) error { return nil },
			daemonLive:                 func() bool { return false },
			setImmutable:               func(string, bool) error { return nil },
			removeAuditd:               func() error { return nil },
			acquireStateLock:           func(string) (func(), error) { return func() {}, nil },
			glob:                       func(string) ([]string, error) { return nil, nil },
			removeWebserverIntegration: removeIntegration,
			remove: func(path string) error {
				*events = append(*events, "remove "+path)
				return nil
			},
			removeAll: func(path string) error {
				*events = append(*events, "removeAll "+path)
				return nil
			},
		},
	}
}

// Every challenge snippet references the map files. Deleting the maps while a
// snippet still points at them breaks the web server's configtest host-wide,
// so uninstall removes the snippets first and only then their maps.
func TestInstallerUninstallRemovesChallengeSnippetsBeforeTheirMaps(t *testing.T) {
	var events []string
	inst := uninstallRecorder(&events, func() error {
		events = append(events, "integration")
		return nil
	})
	if err := inst.Uninstall(false); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(events, "removeAll "+filepath.Dir(challenge.DefaultMapPath)) {
		t.Fatal("uninstall deletes the required Apache site include with the cache directory")
	}
	for _, path := range []string{challenge.DefaultMapPath, challenge.DefaultNginxMapPath} {
		maps := slices.Index(events, "remove "+path)
		if maps < 0 {
			t.Fatalf("challenge map was not removed: %v", events)
		}
		for _, ev := range []string{"integration", "remove /etc/apache2/conf.d/csm_challenge.conf"} {
			if i := slices.Index(events, ev); i < 0 || i > maps {
				t.Errorf("%q must happen before the maps are removed: %v", ev, events)
			}
		}
	}
}

// When a snippet cannot be removed (configtest fails without it, operator
// edits), the maps it references must stay so the web server keeps starting.
// The rest of the uninstall still completes.
func TestInstallerUninstallKeepsChallengeMapsWhenASnippetRemains(t *testing.T) {
	var events []string
	inst := uninstallRecorder(&events, func() error {
		return errors.New("configtest after remove: nginx: unknown variable \"csm_challenged\"")
	})
	if err := inst.Uninstall(false); err != nil {
		t.Fatalf("uninstall must finish when a snippet stays in place: %v", err)
	}
	if slices.Contains(events, "removeAll "+filepath.Dir(challenge.DefaultMapPath)) ||
		slices.Contains(events, "remove "+challenge.DefaultMapPath) ||
		slices.Contains(events, "remove "+challenge.DefaultNginxMapPath) {
		t.Fatalf("challenge maps removed while a snippet still references them: %v", events)
	}
	if !slices.Contains(events, "remove "+inst.BinaryPath) {
		t.Fatalf("binary was not removed: %v", events)
	}
}

func TestUninstallRemovesPeerLogDespiteChallengeFailure(t *testing.T) {
	root := t.TempDir()
	h := &fakeWebserverHandler{snippet: filepath.Join(root, "challenge.conf")}
	peer := filepath.Join(root, "peer.conf")
	for path, body := range map[string]string{h.snippet: "# operator challenge\n", peer: "# csm-managed-version: 1\n"} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := newWebserverIntegration
	newWebserverIntegration = func(*config.Config) (*webserver.Installer, error) {
		return &webserver.Installer{Handler: h, ReadAt: os.ReadFile, WriteAt: os.WriteFile, RemoveAt: os.Remove, PeerLogPath: peer}, nil
	}
	t.Cleanup(func() { newWebserverIntegration = old })
	if err := removeWebserverIntegrationSnippet(); !errors.Is(err, webserver.ErrManualEdits) {
		t.Fatalf("challenge failure lost: %v", err)
	}
	if _, err := os.Stat(peer); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("peer snippet survived: %v", err)
	}
}

// Purge removes CSM's log directory and the peer log directory even when a
// snippet could not be removed: no snippet references CSM's own logs, Apache
// skips the peer log while its directory is missing and LiteSpeed starts
// without it, while a kept peer directory would grow with nothing to bound it.
func TestUninstallPurgeRemovesLogDirectoriesWhenIntegrationRemains(t *testing.T) {
	var events []string
	inst := uninstallRecorder(&events, func() error { return errors.New("snippet remains") })
	inst.StatePath = t.TempDir()
	if err := inst.Uninstall(true); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Dir(inst.LogPath), filepath.Dir(webserver.PeerLogFile)} {
		if !slices.Contains(events, "removeAll "+dir) {
			t.Errorf("purge kept %s", dir)
		}
	}
}
