package checks

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

// Tests for functions that are at 0% coverage and not already tested
// in waf_test.go, plugincheck_test.go, or emailpasswd_test.go.

// --- checkEngineMode (waf.go:345, 0%) ------------------------------------

func TestCheckEngineMode_On(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "modsecurity") {
				tmp := t.TempDir() + "/modsec.conf"
				_ = os.WriteFile(tmp, []byte("SecRuleEngine On\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
	info := platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSApache, ApacheConfigDir: "/etc/apache2"}
	if mode := checkEngineMode(info); mode != "on" {
		t.Errorf("got %q, want on", mode)
	}
}

func TestCheckEngineMode_DetectionOnly(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "modsecurity") {
				tmp := t.TempDir() + "/modsec.conf"
				_ = os.WriteFile(tmp, []byte("SecRuleEngine DetectionOnly\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
	info := platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSApache, ApacheConfigDir: "/etc/apache2"}
	if mode := checkEngineMode(info); mode != "detectiononly" {
		t.Errorf("got %q, want detectiononly", mode)
	}
}

func TestCheckEngineMode_NoConfig(t *testing.T) {
	withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return nil, os.ErrNotExist }})
	info := platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSApache, ApacheConfigDir: "/etc/apache2"}
	if mode := checkEngineMode(info); mode != "" {
		t.Errorf("got %q, want empty", mode)
	}
}

func TestCheckEngineMode_SkipsComments(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "modsecurity") {
				tmp := t.TempDir() + "/modsec.conf"
				_ = os.WriteFile(tmp, []byte("# SecRuleEngine On\nSecRuleEngine Off\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
	info := platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSApache, ApacheConfigDir: "/etc/apache2"}
	if mode := checkEngineMode(info); mode != "off" {
		t.Errorf("got %q, want off", mode)
	}
}

// --- checkPerAccountBypass (waf.go:464, 0%) --------------------------------

func TestCheckPerAccountBypass_NoCmd(t *testing.T) {
	withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) { return nil, fmt.Errorf("not found") }})
	if bypassed := checkPerAccountBypass(); len(bypassed) != 0 {
		t.Errorf("expected empty, got %v", bypassed)
	}
}

func TestCheckPerAccountBypass_WithDisabled(t *testing.T) {
	output := "    example.com:\n      disabled: 1\n    good.com:\n      disabled: 0\n"
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "whmapi1" {
				return []byte(output), nil
			}
			return nil, nil
		},
	})
	bypassed := checkPerAccountBypass()
	if len(bypassed) != 1 || bypassed[0] != "example.com" {
		t.Errorf("expected [example.com], got %v", bypassed)
	}
}

// --- deployVirtualPatches (waf.go:498, 0%) --------------------------------

func TestDeployVirtualPatches_NoSource(t *testing.T) {
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
	deployVirtualPatches() // should not panic
}

func TestDeployVirtualPatches_NoDest(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "csm_modsec_custom") {
				return []byte("# CSM Custom ModSecurity Rules"), nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	})
	deployVirtualPatches() // should not panic
}

// --- autoUpdateWAFRules (waf.go:549, 0%) ----------------------------------

func TestAutoUpdateWAFRules_NoVendors(t *testing.T) {
	withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) { return nil, fmt.Errorf("not found") }})
	if autoUpdateWAFRules() {
		t.Error("expected false")
	}
}

func TestAutoUpdateWAFRules_WithVendors(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "modsec_get_vendors" {
				return []byte("  vendor_id: OWASP\n  vendor_id: comodo\n"), nil
			}
			if len(args) > 0 && args[0] == "modsec_update_vendor" {
				return []byte("result: 1"), nil
			}
			return nil, nil
		},
	})
	if !autoUpdateWAFRules() {
		t.Error("expected true")
	}
}

// --- findAllWPInstalls (plugincheck.go:185, 0%) ---------------------------

func TestFindAllWPInstalls_DeduplicatesAndSkips(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "public_html/wp-config") {
				return []string{
					"/home/alice/public_html/wp-config.php",
					"/home/alice/public_html/staging/wp-config.php",
				}, nil
			}
			if strings.Contains(pattern, "public_html/*/wp-config") {
				return []string{"/home/alice/public_html/blog/wp-config.php"}, nil
			}
			return nil, nil
		},
	})
	results := findAllWPInstalls()
	for _, r := range results {
		if strings.Contains(strings.ToLower(r), "staging") {
			t.Errorf("should have skipped staging: %s", r)
		}
	}
	if len(results) != 2 {
		t.Errorf("expected 2, got %d: %v", len(results), results)
	}
}

// --- discoverShadowFiles (emailpasswd.go, partially covered) ---------------

func TestDiscoverShadowFiles_Found(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "shadow") {
				return []string{"/home/alice/etc/example.com/shadow", "/home/bob/etc/bob.org/shadow"}, nil
			}
			return nil, nil
		},
	})
	files := discoverShadowFiles()
	if len(files) != 2 {
		t.Fatalf("expected 2, got %d", len(files))
	}
	if files[0].account != "alice" || files[0].domain != "example.com" {
		t.Errorf("first: account=%q domain=%q", files[0].account, files[0].domain)
	}
}

func TestDiscoverShadowFiles_Empty(t *testing.T) {
	withMockOS(t, &mockOS{glob: func(string) ([]string, error) { return nil, nil }})
	if files := discoverShadowFiles(); len(files) != 0 {
		t.Errorf("expected empty, got %d", len(files))
	}
}
