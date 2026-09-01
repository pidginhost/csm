package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The legacy snippet makes Apache validate the map at every config parse.
// Install must create the map before the snippet lands, and must not deploy
// a snippet whose map it could not create.
func TestDeployChallengeConfigCreatesMapBeforeSnippet(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "csm_challenge.conf")
	if err := os.WriteFile(src, []byte("RewriteMap csm_challenge \"txt:/var/cache/csm/challenge_ips.txt\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "conf.d", "csm_challenge.conf")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	origSrc, origDest, origEnsure := challengeConfSrc, challengeConfDest, ensureChallengeMapFile
	challengeConfSrc, challengeConfDest = src, dest
	t.Cleanup(func() { challengeConfSrc, challengeConfDest, ensureChallengeMapFile = origSrc, origDest, origEnsure })

	ensured := 0
	ensureChallengeMapFile = func() error {
		ensured++
		if _, err := os.Stat(dest); err == nil {
			t.Error("snippet deployed before its map existed")
		}
		return nil
	}
	(&Installer{}).DeployChallengeConfig()
	if ensured != 1 {
		t.Fatalf("map ensured %d times, want 1", ensured)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("snippet not deployed: %v", err)
	}

	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	ensureChallengeMapFile = func() error { return errors.New("read-only file system") }
	(&Installer{}).DeployChallengeConfig()
	if _, err := os.Stat(dest); err == nil {
		t.Fatal("snippet deployed although its map could not be created")
	}
}
