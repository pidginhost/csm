package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The legacy proxy-mode snippet saw every challenged visitor as the
// loopback address, and it doubled the integration snippet `csm
// webserver-integration install` writes beside it. Install must leave the
// webserver alone: the integration is the only challenge snippet.
func TestInstallDoesNotDeployLegacyChallengeSnippet(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "opt", "csm", "configs", "csm_challenge.conf")
	dest := filepath.Join(root, "etc", "apache2", "conf.d", "csm_challenge.conf")
	for _, d := range []string{filepath.Dir(src), filepath.Dir(dest)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(src, []byte("RewriteMap csm_challenge \"txt:/var/cache/csm/challenge_ips.txt\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	origSrc, origDest, origEnsure := challengeConfSrc, challengeConfDest, ensureChallengeMapFile
	challengeConfSrc, challengeConfDest = src, dest
	ensureChallengeMapFile = func() error { return nil }
	t.Cleanup(func() { challengeConfSrc, challengeConfDest, ensureChallengeMapFile = origSrc, origDest, origEnsure })

	inst := &Installer{
		BinaryPath:  filepath.Join(root, "opt", "csm", "csm"),
		CommandPath: filepath.Join(root, "usr", "sbin", "csm"),
		ConfigPath:  filepath.Join(root, "etc", "csm", "csm.yaml"),
		StatePath:   filepath.Join(root, "var", "lib", "csm", "state"),
		LogPath:     filepath.Join(root, "var", "log", "csm", "monitor.log"),
		operations: &installerOperations{
			getuid:          func() int { return 0 },
			deployAuditd:    func() error { return nil },
			deploySystemd:   func() error { return nil },
			deployLogrotate: func() error { return nil },
			setImmutable:    func(string, bool) error { return nil },
		},
	}
	if err := inst.Install(); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("install deployed the legacy challenge snippet (stat: %v)", err)
	}
}
