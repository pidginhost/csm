package webui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

const testShieldPath = "/opt/csm/php_shield.php"

func fakeProc(t *testing.T, root, pid, cmdline string, shield bool) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(filepath.Join(dir, "root"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644); err != nil {
		t.Fatal(err)
	}
	if shield {
		p := filepath.Join(dir, "root", testShieldPath)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("<?php\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestScanPHPProcesses(t *testing.T) {
	cases := []struct {
		name              string
		procs             map[string]string // pid -> cmdline
		shieldPID         string
		running, shielded bool
	}{
		{"no PHP", map[string]string{"10": "nginx: worker process\x00"}, "10", false, false},
		{"container fpm worker", map[string]string{"10": "php-fpm: pool www\x00"}, "", true, false},
		{"idle ondemand pool", map[string]string{"10": "php-fpm: master process (/usr/local/etc/php-fpm.conf)\x00"}, "", true, false},
		{"lsphp", map[string]string{"10": "lsphp\x00"}, "", true, false},
		{"shield in a PHP container", map[string]string{"10": "nginx: worker process\x00", "20": "php-fpm: pool www\x00"}, "20", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			for pid, cmd := range c.procs {
				fakeProc(t, root, pid, cmd, pid == c.shieldPID)
			}
			running, shielded := scanPHPProcesses(root, testShieldPath)
			if running != c.running || shielded != c.shielded {
				t.Errorf("got running=%v shielded=%v, want %v %v", running, shielded, c.running, c.shielded)
			}
		})
	}
}

// A container cannot claim the shield with a symlink to the host's copy.
func TestScanPHPProcessesIgnoresShieldSymlink(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, "10", "php-fpm: pool www\x00", false)
	target := filepath.Join(t.TempDir(), "php_shield.php")
	if err := os.WriteFile(target, []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "10", "root", testShieldPath)
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if running, shielded := scanPHPProcesses(root, testShieldPath); !running || shielded {
		t.Errorf("got running=%v shielded=%v, want true false", running, shielded)
	}
}

func TestPHPShieldSectionNeedsShieldedPHP(t *testing.T) {
	shield, _ := LookupSettingsSection("php_shield")
	if _, ok := filterSettingsSection(shield, map[string]bool{"php": true}); ok {
		t.Error("php_shield shown for container PHP the shield does not reach")
	}
	if _, ok := filterSettingsSection(shield, map[string]bool{"php": true, "phpShield": true}); !ok {
		t.Error("php_shield hidden although the shield reaches PHP")
	}
}

func TestUIFeaturesPHPShieldFollowsDetection(t *testing.T) {
	got := uiFeatures(platform.Info{Panel: platform.PanelNone}, platform.MTAUnknown, phpPresence{php: true})
	if !got["php"] || got["phpShield"] {
		t.Errorf("container PHP without shield: %v", got)
	}
	got = uiFeatures(platform.Info{Panel: platform.PanelNone}, platform.MTAUnknown, phpPresence{php: true, shield: true})
	if !got["php"] || !got["phpShield"] {
		t.Errorf("shielded PHP: %v", got)
	}
}
