package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// The registry deploy script once installed an unsigned "latest" build. Every
// build the registry serves is now signed, so a hand-kept copy that still
// carries that exception lets a build with its signature stripped install,
// while the shipped scripts must not be reported.
func TestDeployScriptCheckReportsUnsignedBuildException(t *testing.T) {
	stale := filepath.Join(t.TempDir(), "deploy-csm.sh")
	const body = `#!/bin/bash
verify_signature() {
    if unsigned_ci_build "$release_version"; then
        return 0
    fi
}
`
	if err := os.WriteFile(stale, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if !deployScriptSkipsVerification(stale) {
		t.Error("copy that accepts unsigned registry builds not reported")
	}
	for _, name := range []string{"deploy.sh", "deploy-gitlab.sh"} {
		path := filepath.Join("..", "..", "scripts", name)
		if _, err := os.Stat(path); err != nil {
			// The public mirror does not carry the internal registry script.
			if name == "deploy-gitlab.sh" && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			t.Fatal(err)
		}
		if deployScriptSkipsVerification(path) {
			t.Errorf("shipped scripts/%s reported as able to install an unverified release", name)
		}
	}
}
