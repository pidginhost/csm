package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// The registry deploy script once installed an unsigned "latest" build. A
// hand-kept copy that still carries that exception must be reported, as a
// warning: upgrade health checks roll back on a doctor failure, and a stale
// operator script must not undo an upgrade. The shipped scripts stay OK.
func TestDeployScriptCheckReportsUnsignedBuildException(t *testing.T) {
	const body = `#!/bin/bash
verify_signature() {
    if unsigned_ci_build "$release_version"; then
        return 0
    fi
}
`
	path := "/root/deploy-csm.sh"
	if got := deployScriptStatus(path, path, []byte(body)); got != "warn" {
		t.Errorf("copy that accepts unsigned registry builds: got %q, want warn", got)
	}
	for _, name := range []string{"deploy.sh", "deploy-gitlab.sh"} {
		shipped := filepath.Join("..", "..", "scripts", name)
		data, err := os.ReadFile(shipped)
		if err != nil {
			// The public mirror does not carry the internal registry script.
			if name == "deploy-gitlab.sh" && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			t.Fatal(err)
		}
		if got := deployScriptStatus("/root/"+name, "/root/"+name, data); got != "ok" {
			t.Errorf("shipped scripts/%s: got %q, want ok", name, got)
		}
	}
}
