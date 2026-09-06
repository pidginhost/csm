package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCPanelReleasePreflight(t *testing.T) {
	bin := t.TempDir()
	phctl := `#!/usr/bin/env bash
[ "${CPANEL_IMAGE_LIST_FAIL:-}" != 1 ] || exit 1
printf 'ID  NAME  SLUG\n91  cPanel WHM  csm-cpanel-a9-20260905\n'
`
	if err := os.WriteFile(filepath.Join(bin, "phctl"), []byte(phctl), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("INTEGRATION_CPANEL_PACKAGE", "")

	for _, tc := range []struct {
		name, tag, image, waiver string
		valid                    bool
	}{
		{name: "ordinary branch", valid: true},
		{name: "release without image", tag: "v9.0.0"},
		{name: "release with image", tag: "v9.0.0", image: "csm-cpanel-a9-20260905", valid: true},
		{name: "invalid image", tag: "v9.0.0", image: "name with spaces"},
		{name: "unavailable image", tag: "v9.0.0", image: "missing"},
		{name: "numeric image", tag: "v9.0.0", image: "91", valid: true},
		{name: "inventory failure", tag: "v9.0.0", image: "91"},
		// No cPanel licence is available to this project. Releasing without
		// that coverage must be a recorded decision, never a silent warning.
		{name: "acknowledged absence", tag: "v9.0.0", waiver: "no licensed cPanel image available", valid: true},
		{name: "acknowledged absence needs a reason", tag: "v9.0.0", waiver: "1"},
		{name: "acknowledgement cannot excuse a broken image", tag: "v9.0.0", image: "missing", waiver: "no licensed cPanel image available"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "ci-cpanel-preflight.sh")
			cmd.Env = append(os.Environ(), "CI_COMMIT_TAG="+tc.tag, "INTEGRATION_CPANEL_IMAGE="+tc.image,
				"CSM_RELEASE_WITHOUT_CPANEL="+tc.waiver)
			if tc.name == "inventory failure" {
				cmd.Env = append(cmd.Env, "CPANEL_IMAGE_LIST_FAIL=1")
			}
			output, err := cmd.CombinedOutput()
			if (err == nil) != tc.valid {
				t.Fatalf("error=%v output=%s", err, output)
			}
			if !tc.valid && !strings.Contains(string(output), "ERROR:") {
				t.Fatalf("missing diagnosis: %s", output)
			}
			// A release published without cPanel coverage must say so in its
			// own log, not only in whoever set the variable's memory.
			if tc.valid && tc.waiver != "" && !strings.Contains(string(output), "WITHOUT cPanel coverage") {
				t.Fatalf("release evidence does not disclose the gap: %s", output)
			}
		})
	}
}
