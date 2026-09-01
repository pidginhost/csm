package main

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/challenge"
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
	maps := slices.Index(events, "removeAll "+filepath.Dir(challenge.DefaultMapPath))
	if maps < 0 {
		t.Fatalf("challenge map directory was not removed: %v", events)
	}
	for _, ev := range []string{"integration", "remove /etc/apache2/conf.d/csm_challenge.conf"} {
		if i := slices.Index(events, ev); i < 0 || i > maps {
			t.Errorf("%q must happen before the maps are removed: %v", ev, events)
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
	if slices.Contains(events, "removeAll "+filepath.Dir(challenge.DefaultMapPath)) {
		t.Fatalf("challenge maps removed while a snippet still references them: %v", events)
	}
	if !slices.Contains(events, "remove "+inst.BinaryPath) {
		t.Fatalf("binary was not removed: %v", events)
	}
}
