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
		name, tag, image string
		valid            bool
	}{
		{"ordinary branch", "", "", true},
		{"release without image", "v9.0.0", "", false},
		{"release with image", "v9.0.0", "csm-cpanel-a9-20260905", true},
		{"invalid image", "v9.0.0", "name with spaces", false},
		{"unavailable image", "v9.0.0", "missing", false},
		{"numeric image", "v9.0.0", "91", true},
		{"inventory failure", "v9.0.0", "91", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "ci-cpanel-preflight.sh")
			cmd.Env = append(os.Environ(), "CI_COMMIT_TAG="+tc.tag, "INTEGRATION_CPANEL_IMAGE="+tc.image)
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
		})
	}
}
