package daemon

import (
	"os"
	"path/filepath"
)

// Daemon tests start the antispam loops; none may touch a host's real CSM
// IP map. The directory does not exist, so removal is a no-op.
func init() {
	antispamIPMapPath = filepath.Join(os.TempDir(), "csm-daemon-test-no-ipmap", "csm_ip.map")
}
