package challenge

import (
	"path/filepath"
	"strings"
	"testing"
)

// Apache and LSWS validate a txt: RewriteMap at config-parse time and nginx
// fails on a missing include. The map files are therefore part of the web
// server's configuration and must exist whenever it starts or reloads, which
// includes every moment CSM itself is stopped: package upgrades, restores,
// reboots. A path under the service's RuntimeDirectory is deleted by systemd
// on every stop, so it can never satisfy that.
func TestDefaultMapPathsOutliveTheService(t *testing.T) {
	for _, p := range []string{DefaultMapPath, DefaultNginxMapPath} {
		if strings.HasPrefix(p, "/run/") || strings.HasPrefix(p, "/var/run/") {
			t.Errorf("%s lives under the runtime directory and vanishes whenever csm stops", p)
		}
		if !filepath.IsAbs(p) {
			t.Errorf("%s is not absolute", p)
		}
	}
	if filepath.Dir(DefaultMapPath) != filepath.Dir(DefaultNginxMapPath) {
		t.Errorf("the two maps must share one directory: %s vs %s", DefaultMapPath, DefaultNginxMapPath)
	}
}
