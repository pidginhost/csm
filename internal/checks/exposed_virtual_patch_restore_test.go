package checks

import (
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/safepath"
)

func virtualPatchRestoreTarget(t *testing.T, path string) *safepath.Target {
	t.Helper()
	target, err := safepath.OpenTarget(filepath.Dir(path), filepath.Base(path), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(target.Close)
	return target
}
