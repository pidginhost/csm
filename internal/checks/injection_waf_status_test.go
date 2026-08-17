package checks

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// Comprehensive tests for CheckWAFStatus driving every branch via
// platform.SetOverrides + cmdExec/osFS mocks.

func TestCheckWAFStatusNoWebServerEarlyReturn(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel:           ptrPanel(platform.PanelNone),
		WebServer:       ptrWebServer(platform.WSNone),
		ApacheConfigDir: "",
		NginxConfigDir:  "",
	})

	findings := CheckWAFStatus(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no web server should yield 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestCheckWAFStatusModSecNotActiveCriticalFinding(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel:           ptrPanel(platform.PanelNone),
		WebServer:       ptrWebServer(platform.WSApache),
		ApacheConfigDir: "/etc/apache2",
	})
	// Mock OS so modsecDetected returns false (no mod_security2.conf, no
	// .so module loaded, no SecRuleEngine directive in scanned configs).
	withMockOS(t, &mockOS{
		open: func(string) (*os.File, error) { return nil, os.ErrNotExist },
		stat: func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	})
	withMockCmd(t, &mockCmd{})

	findings := CheckWAFStatus(context.Background(), &config.Config{}, nil)
	found := false
	for _, f := range findings {
		if f.Check == "waf_status" && f.Severity == alert.Critical {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected critical waf_status finding when modsec not active, got: %+v", findings)
	}
}

func TestCheckWAFStatusDetectionOnlyEmitsHigh(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel:           ptrPanel(platform.PanelNone),
		WebServer:       ptrWebServer(platform.WSApache),
		ApacheConfigDir: "/etc/apache2",
	})

	// modsecDetected reads an Apache config that activates modsec. We mock
	// osFS.Open to return a file with the activation directive (LoadModule
	// security2_module is what the detector checks for).
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			tmp, _ := os.CreateTemp(t.TempDir(), "mod")
			if strings.Contains(name, "modsecurity") || strings.Contains(name, "security2") {
				_, _ = tmp.WriteString("LoadModule security2_module modules/mod_security2.so\nSecRuleEngine DetectionOnly\n")
				_, _ = tmp.Seek(0, 0)
				return tmp, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "modsecurity") || strings.Contains(name, "security2") {
				return []byte("LoadModule security2_module modules/mod_security2.so\nSecRuleEngine DetectionOnly\n"), nil
			}
			return nil, os.ErrNotExist
		},
		readDir: func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
	})
	withMockCmd(t, &mockCmd{})

	findings := CheckWAFStatus(context.Background(), &config.Config{}, nil)
	// We may also get waf_rules finding (no rules present), that's fine.
	hasDetectionOnly := false
	for _, f := range findings {
		if f.Check == "waf_detection_only" && f.Severity == alert.High {
			hasDetectionOnly = true
			break
		}
	}
	if !hasDetectionOnly {
		t.Errorf("expected high waf_detection_only finding, got: %+v", findings)
	}
}

func TestCheckWAFStatusNoRulesEmitsHigh(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel:           ptrPanel(platform.PanelCPanel),
		WebServer:       ptrWebServer(platform.WSApache),
		ApacheConfigDir: "/usr/local/apache",
	})

	// ModSecurity is installed, but cPanel and the filesystem report no rules.
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name != "whmapi1" || len(args) == 0 {
				return nil, nil
			}
			switch args[0] {
			case "modsec_is_installed":
				return []byte("installed: 1\n"), nil
			case "modsec_get_configs":
				if len(args) == 2 && args[1] == "--output=json" {
					return []byte(`{"data":{"configs":[]},"metadata":{"result":1}}`), nil
				}
				return []byte(""), nil
			case "modsec_get_vendors":
				return []byte("vendors: []\n"), nil
			}
			return nil, nil
		},
	})
	// Mock readDir to return no rule artifacts.
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			tmp, _ := os.CreateTemp(t.TempDir(), "mod")
			if strings.Contains(name, "modsecurity") || strings.Contains(name, "modsec") {
				_, _ = tmp.WriteString("SecRuleEngine On\n")
				_, _ = tmp.Seek(0, 0)
				return tmp, nil
			}
			return nil, os.ErrNotExist
		},
		readDir: func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
		stat:    func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	})

	findings := CheckWAFStatus(context.Background(), &config.Config{}, nil)
	for _, finding := range findings {
		if finding.Check == "waf_rules" && finding.Severity == alert.High {
			return
		}
	}
	t.Fatalf("expected high waf_rules finding, got: %+v", findings)
}

func TestCheckWAFStatusInactiveVendorConfigDoesNotCountAsLoaded(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel:           ptrPanel(platform.PanelCPanel),
		WebServer:       ptrWebServer(platform.WSApache),
		ApacheConfigDir: "/usr/local/apache",
	})

	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
		if name != "whmapi1" || len(args) == 0 {
			return nil, nil
		}
		switch args[0] {
		case "modsec_is_installed":
			return []byte("installed: 1\n"), nil
		case "modsec_get_configs":
			if len(args) == 2 && args[1] == "--output=json" {
				return []byte(`{"data":{"configs":[{"active":0,"config":"modsec_vendor_configs/OWASP3/rules.conf","vendor_id":"OWASP3"}]},"metadata":{"result":1}}`), nil
			}
			return []byte(""), nil
		case "modsec_get_vendors":
			if len(args) == 2 && args[1] == "--output=json" {
				return []byte(`{"data":{"vendors":[{"enabled":1,"installed":1,"path":"/usr/local/apache/conf/modsec_vendor_configs/OWASP3","vendor_id":"OWASP3"}]},"metadata":{"result":1}}`), nil
			}
			return []byte("vendor_id: OWASP3\nenabled: 1\n"), nil
		}
		return nil, nil
	}})
	withMockOS(t, &mockOS{readDir: func(name string) ([]os.DirEntry, error) {
		switch name {
		case "/usr/local/apache/conf/modsec_vendor_configs":
			return []os.DirEntry{testDirEntry{name: "OWASP3", isDir: true}}, nil
		case "/usr/local/apache/conf/modsec_vendor_configs/OWASP3":
			return []os.DirEntry{testDirEntry{name: "REQUEST-901-INITIALIZATION.conf"}}, nil
		}
		return nil, os.ErrNotExist
	}})

	findings := CheckWAFStatus(context.Background(), &config.Config{}, nil)
	for _, finding := range findings {
		if finding.Check == "waf_rules" && finding.Severity == alert.High {
			return
		}
	}
	t.Fatalf("expected inactive vendor config to produce waf_rules finding, got: %+v", findings)
}

func TestProbeWAFRulesCountsActiveCustomConfig(t *testing.T) {
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
		if name != "whmapi1" || len(args) != 2 || args[0] != "modsec_get_configs" || args[1] != "--output=json" {
			return nil, fmt.Errorf("unexpected command: %s %v", name, args)
		}
		return []byte(`{"data":{"configs":[{"active":1,"config":"modsec2.custom.conf","vendor_id":""}]},"metadata":{"result":1}}`), nil
	}})

	info := platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSApache}
	if !probeWAFRules(info, nil) {
		t.Fatal("an active custom ModSecurity config must count as loaded rules")
	}
}

// Regression for the cPanel+LiteSpeed false positive seen at 01:00:55 when
// cPanel's nightly modsec_assemble job was mid-rebuild. whmapi1
// modsec_get_configs transiently returns no active configs. The filesystem
// backstop must still recognize the vendor rules already visible on disk.
func TestCheckWAFStatusCPanelLiteSpeedVendorDirBackstopsEmptyWhmapi1(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel:     ptrPanel(platform.PanelCPanel),
		WebServer: ptrWebServer(platform.WSLiteSpeed),
	})

	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name != "whmapi1" || len(args) == 0 {
				return nil, nil
			}
			switch args[0] {
			case "modsec_is_installed":
				return []byte("installed: 1\n"), nil
			case "modsec_get_configs":
				if len(args) == 2 && args[1] == "--output=json" {
					// Reassembly window: WHM has not re-populated its active
					// config list, but assembled rules are already visible.
					return []byte(`{"data":{"configs":[]},"metadata":{"result":1}}`), nil
				}
				return []byte(""), nil
			}
			return nil, nil
		},
	})

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/etc/apache2/conf.d/modsec_vendor_configs":
				return []os.DirEntry{testDirEntry{name: "comodo_litespeed", isDir: true}}, nil
			case "/etc/apache2/conf.d/modsec_vendor_configs/comodo_litespeed":
				return []os.DirEntry{
					testDirEntry{name: "10_HTTP_HTTP.conf", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckWAFStatus(context.Background(), &config.Config{}, nil)
	for _, f := range findings {
		if f.Check == "waf_rules" {
			t.Errorf("waf_rules should not fire when vendor rules exist on disk even if whmapi1 returns empty; got %+v", f)
		}
	}
}

// Regression for the production false positive at 01:10:27. Same race as
// the LiteSpeed-backstop test, but the filesystem ALSO returned empty
// during cPanel's modsec_assemble window (vendor dir is rewritten in
// place, no temp-rename atomicity). On cPanel+LiteSpeed the check
// re-probes once after a short delay before alerting; if the re-probe
// finds rules the alert is suppressed entirely, so the flap doesn't
// page and a real "no rules" host still alerts within the same scan.
func TestCheckWAFStatusModsecAssembleRetryRecovers(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel:     ptrPanel(platform.PanelCPanel),
		WebServer: ptrWebServer(platform.WSLiteSpeed),
	})

	prevDelay := wafRulesAssembleRetryDelay
	wafRulesAssembleRetryDelay = 1 * time.Millisecond
	t.Cleanup(func() { wafRulesAssembleRetryDelay = prevDelay })

	// modsec is "active" so the rule-vendor branch is reached.
	modsecOnFile := func(name string) (*os.File, error) {
		if strings.Contains(name, "modsec") || strings.Contains(name, "security2") {
			tmp, _ := os.CreateTemp(t.TempDir(), "mod")
			_, _ = tmp.WriteString("LoadModule security2_module modules/mod_security2.so\nSecRuleEngine On\n")
			_, _ = tmp.Seek(0, 0)
			return tmp, nil
		}
		return nil, os.ErrNotExist
	}
	modsecReadFile := func(name string) ([]byte, error) {
		if strings.Contains(name, "modsec") || strings.Contains(name, "security2") {
			return []byte("LoadModule security2_module modules/mod_security2.so\nSecRuleEngine On\n"), nil
		}
		return nil, os.ErrNotExist
	}

	// The first active-config call returns empty (mid-rewrite); the second reports
	// an active vendor config. modsec_is_installed always returns "installed".
	getConfigsCalls := 0
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name != "whmapi1" || len(args) == 0 {
				return nil, nil
			}
			switch args[0] {
			case "modsec_is_installed":
				return []byte("installed: 1\n"), nil
			case "modsec_get_configs":
				if len(args) == 2 && args[1] == "--output=json" {
					getConfigsCalls++
					if getConfigsCalls == 1 {
						return []byte(`{"data":{"configs":[]},"metadata":{"result":1}}`), nil
					}
					return []byte(`{"data":{"configs":[{"active":1,"config":"modsec_vendor_configs/comodo_litespeed/rules.conf","vendor_id":"comodo_litespeed"}]},"metadata":{"result":1}}`), nil
				}
				return []byte(""), nil
			case "modsec_get_vendors":
				if len(args) == 2 && args[1] == "--output=json" {
					return []byte(`{"data":{"vendors":[{"enabled":1,"installed":1,"path":"/etc/apache2/conf.d/modsec_vendor_configs/comodo_litespeed","vendor_id":"comodo_litespeed"}]},"metadata":{"result":1}}`), nil
				}
				return []byte(""), nil
			}
			return nil, nil
		},
	})
	// Filesystem stays empty across both probes -- recovery comes from
	// the second whmapi1 call alone.
	withMockOS(t, &mockOS{
		open:     modsecOnFile,
		readFile: modsecReadFile,
		readDir:  func(string) ([]os.DirEntry, error) { return nil, nil },
		stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	})

	findings := CheckWAFStatus(context.Background(), &config.Config{}, nil)
	for _, f := range findings {
		if f.Check == "waf_rules" {
			t.Fatalf("retry recovery should suppress waf_rules; got %+v", f)
		}
	}
	if getConfigsCalls != 3 {
		t.Errorf("active-config calls = %d, want initial probe, retry, and age check", getConfigsCalls)
	}
}

// Real "no rules" cPanel+LiteSpeed host: both probes empty. The check
// must still alert in the same scan (don't shift detection to the
// next deep tier) -- the retry is a debounce, not a defer.
func TestCheckWAFStatusModsecAssembleRetryStillAlertsWhenTrulyEmpty(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel:     ptrPanel(platform.PanelCPanel),
		WebServer: ptrWebServer(platform.WSLiteSpeed),
	})

	prevDelay := wafRulesAssembleRetryDelay
	wafRulesAssembleRetryDelay = 1 * time.Millisecond
	t.Cleanup(func() { wafRulesAssembleRetryDelay = prevDelay })

	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name != "whmapi1" || len(args) == 0 {
				return nil, nil
			}
			switch args[0] {
			case "modsec_is_installed":
				return []byte("installed: 1\n"), nil
			case "modsec_get_configs":
				if len(args) == 2 && args[1] == "--output=json" {
					return []byte(`{"data":{"configs":[]},"metadata":{"result":1}}`), nil
				}
			}
			return []byte(""), nil
		},
	})
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "modsec") || strings.Contains(name, "security2") {
				tmp, _ := os.CreateTemp(t.TempDir(), "mod")
				_, _ = tmp.WriteString("LoadModule security2_module modules/mod_security2.so\nSecRuleEngine On\n")
				_, _ = tmp.Seek(0, 0)
				return tmp, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "modsec") || strings.Contains(name, "security2") {
				return []byte("LoadModule security2_module modules/mod_security2.so\nSecRuleEngine On\n"), nil
			}
			return nil, os.ErrNotExist
		},
		readDir: func(string) ([]os.DirEntry, error) { return nil, nil },
		stat:    func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	})

	findings := CheckWAFStatus(context.Background(), &config.Config{}, nil)
	hasRulesAlert := false
	for _, f := range findings {
		if f.Check == "waf_rules" {
			hasRulesAlert = true
			break
		}
	}
	if !hasRulesAlert {
		t.Fatalf("genuine no-rules host must alert in the same scan after retry; findings=%+v", findings)
	}
}

// Helpers for taking address of constants for Overrides.
func ptrPanel(p platform.Panel) *platform.Panel             { return &p }
func ptrWebServer(w platform.WebServer) *platform.WebServer { return &w }

// forceCPanelPlatform makes platform.Detect() report cPanel for the duration
// of a test. cPanel-only checks (webmail / WHM-API access-log parsing) gate
// on this, so tests exercising them must declare the platform explicitly.
func forceCPanelPlatform(t *testing.T) {
	t.Helper()
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{Panel: ptrPanel(platform.PanelCPanel)})
}
