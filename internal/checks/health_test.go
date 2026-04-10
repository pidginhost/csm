package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

func TestPlatformRequiredCommands_CPanel(t *testing.T) {
	info := platform.Info{Panel: platform.PanelCPanel}
	cmds := platformRequiredCommands(info)
	if !containsStr(cmds, "find") || !containsStr(cmds, "auditctl") || !containsStr(cmds, "exim") {
		t.Errorf("cPanel required commands incomplete: %v", cmds)
	}
}

func TestPlatformRequiredCommands_PlainLinux(t *testing.T) {
	info := platform.Info{OS: platform.OSUbuntu}
	cmds := platformRequiredCommands(info)
	if !containsStr(cmds, "find") || !containsStr(cmds, "auditctl") {
		t.Errorf("plain Linux must still require find + auditctl: %v", cmds)
	}
	if containsStr(cmds, "exim") {
		t.Errorf("plain Linux must NOT require exim: %v", cmds)
	}
}

func containsStr(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
