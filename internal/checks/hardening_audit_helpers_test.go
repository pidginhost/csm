package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

// hexToIPv4 and isPrivateOrLoopback tests are in coverage_test.go.

// --- parsePHPIni ------------------------------------------------------

func TestParsePHPIniStandard(t *testing.T) {
	content := `; comment
[PHP]
display_errors = Off
max_execution_time = 30
memory_limit = 128M
`
	ini := parsePHPIni(content)
	if ini["display_errors"] != "Off" {
		t.Errorf("display_errors = %q", ini["display_errors"])
	}
	if ini["max_execution_time"] != "30" {
		t.Errorf("max_execution_time = %q", ini["max_execution_time"])
	}
	if ini["memory_limit"] != "128M" {
		t.Errorf("memory_limit = %q", ini["memory_limit"])
	}
}

func TestParsePHPIniCommentOnly(t *testing.T) {
	ini := parsePHPIni("; just a comment\n[section]\n")
	if len(ini) != 0 {
		t.Errorf("comment-only input should return empty, got %v", ini)
	}
}

// --- parsePHPVersion --------------------------------------------------

func TestParsePHPVersionStandard(t *testing.T) {
	major, minor := parsePHPVersion("8.2.15")
	if major != 8 || minor != 2 {
		t.Errorf("got (%d, %d), want (8, 2)", major, minor)
	}
}

func TestParsePHPVersionShort(t *testing.T) {
	major, minor := parsePHPVersion("7")
	if major != 0 || minor != 0 {
		t.Errorf("single number should return (0,0), got (%d, %d)", major, minor)
	}
}

func TestParsePHPVersionEmpty(t *testing.T) {
	major, minor := parsePHPVersion("")
	if major != 0 || minor != 0 {
		t.Errorf("empty should return (0,0), got (%d, %d)", major, minor)
	}
}

// --- parseCpanelConfig ------------------------------------------------

func TestParseCpanelConfigStandard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cpanel.config")
	content := "# comment\nskipboxcheck=1\nallow_deprecated_accesshash=1\n\n"
	_ = os.WriteFile(path, []byte(content), 0600)

	conf := parseCpanelConfig(path)
	if conf["skipboxcheck"] != "1" {
		t.Errorf("skipboxcheck = %q", conf["skipboxcheck"])
	}
	if conf["allow_deprecated_accesshash"] != "1" {
		t.Errorf("accesshash = %q", conf["allow_deprecated_accesshash"])
	}
}

func TestParseCpanelConfigMissing(t *testing.T) {
	conf := parseCpanelConfig(filepath.Join(t.TempDir(), "nope"))
	if len(conf) != 0 {
		t.Errorf("missing file should return empty, got %v", conf)
	}
}

// --- evaluateDistroEOL ------------------------------------------------

func TestEvaluateDistroEOLCentOS(t *testing.T) {
	info := platform.Info{OS: platform.OSCentOS, OSVersion: "8.5"}
	results := evaluateDistroEOL(info, "CentOS Linux release 8.5")
	if len(results) != 1 || results[0].Status != "fail" {
		t.Errorf("CentOS should always fail EOL: %+v", results)
	}
}

func TestEvaluateDistroEOLUbuntuCurrent(t *testing.T) {
	info := platform.Info{OS: platform.OSUbuntu, OSVersion: "24.04"}
	results := evaluateDistroEOL(info, "Ubuntu 24.04 LTS")
	if len(results) != 1 || results[0].Status != "pass" {
		t.Errorf("Ubuntu 24.04 should pass: %+v", results)
	}
}

func TestEvaluateDistroEOLUbuntuOld(t *testing.T) {
	info := platform.Info{OS: platform.OSUbuntu, OSVersion: "18.04"}
	results := evaluateDistroEOL(info, "Ubuntu 18.04 LTS")
	if len(results) != 1 || results[0].Status != "fail" {
		t.Errorf("Ubuntu 18.04 should fail: %+v", results)
	}
}

func TestEvaluateDistroEOLUnknownOS(t *testing.T) {
	info := platform.Info{OS: platform.OSUnknown, OSVersion: ""}
	results := evaluateDistroEOL(info, "")
	if len(results) != 1 || results[0].Status != "warn" {
		t.Errorf("unknown OS should warn: %+v", results)
	}
}

func TestEvaluateDistroEOLAlmaCurrent(t *testing.T) {
	info := platform.Info{OS: platform.OSAlma, OSVersion: "9.3"}
	results := evaluateDistroEOL(info, "AlmaLinux 9.3")
	if len(results) != 1 || results[0].Status != "pass" {
		t.Errorf("Alma 9 should pass: %+v", results)
	}
}
