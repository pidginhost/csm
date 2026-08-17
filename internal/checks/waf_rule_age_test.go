package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/platform"
)

type cPanelRuleAgeVendor struct {
	ID      string
	Path    string
	Enabled bool
	Active  bool
}

func withCPanelRuleAgeVendors(t *testing.T, vendors ...cPanelRuleAgeVendor) {
	t.Helper()
	apiVendors := make([]map[string]any, 0, len(vendors))
	apiConfigs := make([]map[string]any, 0, len(vendors))
	for _, vendor := range vendors {
		enabled := 0
		if vendor.Enabled {
			enabled = 1
		}
		apiVendors = append(apiVendors, map[string]any{
			"enabled":   enabled,
			"installed": 1,
			"path":      vendor.Path,
			"vendor_id": vendor.ID,
		})
		active := 0
		if vendor.Active {
			active = 1
		}
		apiConfigs = append(apiConfigs, map[string]any{
			"active":    active,
			"config":    filepath.Join("modsec_vendor_configs", vendor.ID, "rules.conf"),
			"vendor_id": vendor.ID,
		})
	}
	vendorsBody, err := json.Marshal(map[string]any{
		"data":     map[string]any{"vendors": apiVendors},
		"metadata": map[string]any{"result": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	configsBody, err := json.Marshal(map[string]any{
		"data":     map[string]any{"configs": apiConfigs},
		"metadata": map[string]any{"result": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
		if name != "whmapi1" || len(args) != 2 || args[1] != "--output=json" {
			return nil, fmt.Errorf("unexpected command: %s %v", name, args)
		}
		switch args[0] {
		case "modsec_get_configs":
			return configsBody, nil
		case "modsec_get_vendors":
			return vendorsBody, nil
		default:
			return nil, fmt.Errorf("unexpected command: %s %v", name, args)
		}
	}})
}

func cPanelRuleAgeInfo() platform.Info {
	return platform.Info{
		OS:        platform.OSCloudLinux,
		Panel:     platform.PanelCPanel,
		WebServer: platform.WSLiteSpeed,
	}
}

func wafVendorDir(t *testing.T, root, vendor string, age time.Duration) string {
	t.Helper()
	dir := filepath.Join(root, vendor)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rule := filepath.Join(dir, "REQUEST-901-INITIALIZATION.conf")
	if err := os.WriteFile(rule, []byte("SecRule ..."), 0o644); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(rule, when, when); err != nil {
		t.Fatal(err)
	}
	return dir
}

// cPanel leaves a retired vendor's rule tree on disk after an operator switches
// to another one. On a live host OWASP3 was refreshed the same day while the
// abandoned COMODO tree sat at 31 days, and CSM reported "rules are 31 days
// old" -- pointing at a ruleset that no longer protects anything.
func TestCheckRuleAgeIgnoresAbandonedVendorWhenAnotherIsCurrent(t *testing.T) {
	root := t.TempDir()
	retired := wafVendorDir(t, root, "comodo_litespeed", 31*24*time.Hour)
	active := wafVendorDir(t, root, "OWASP3", 2*time.Hour)
	withCPanelRuleAgeVendors(t,
		cPanelRuleAgeVendor{ID: "comodo_litespeed", Path: retired},
		cPanelRuleAgeVendor{ID: "OWASP3", Path: active, Enabled: true, Active: true},
	)

	if age := checkRuleAge(cPanelRuleAgeInfo(), []string{root}); age != 0 {
		t.Errorf("a currently-maintained ruleset must not be reported stale, got age=%d", age)
	}
}

// Each active vendor is a loaded ruleset. Report the least recently refreshed
// one rather than allowing a newer second vendor to hide it.
func TestCheckRuleAgeReportsWhenEveryVendorIsStale(t *testing.T) {
	root := t.TempDir()
	comodo := wafVendorDir(t, root, "comodo_litespeed", 90*24*time.Hour)
	owasp := wafVendorDir(t, root, "OWASP3", 45*24*time.Hour)
	withCPanelRuleAgeVendors(t,
		cPanelRuleAgeVendor{ID: "comodo_litespeed", Path: comodo, Enabled: true, Active: true},
		cPanelRuleAgeVendor{ID: "OWASP3", Path: owasp, Enabled: true, Active: true},
	)

	age := checkRuleAge(cPanelRuleAgeInfo(), []string{root})
	if age < 89 || age > 91 {
		t.Errorf("age = %d, want the stalest active ruleset's age (~90 days)", age)
	}
}

func TestCheckRuleAgeReportsSingleActiveStaleVendor(t *testing.T) {
	root := t.TempDir()
	vendor := wafVendorDir(t, root, "comodo_litespeed", 60*24*time.Hour)
	withCPanelRuleAgeVendors(t, cPanelRuleAgeVendor{
		ID: "comodo_litespeed", Path: vendor, Enabled: true, Active: true,
	})

	if age := checkRuleAge(cPanelRuleAgeInfo(), []string{root}); age < 59 || age > 61 {
		t.Errorf("age = %d, want the active ruleset age (~60 days)", age)
	}
}

func TestCheckRuleAgeReportsStaleActiveVendorAcrossMultipleRuleDirs(t *testing.T) {
	stale := t.TempDir()
	fresh := t.TempDir()
	comodo := wafVendorDir(t, stale, "comodo_litespeed", 40*24*time.Hour)
	owasp := wafVendorDir(t, fresh, "OWASP3", time.Hour)
	withCPanelRuleAgeVendors(t,
		cPanelRuleAgeVendor{ID: "comodo_litespeed", Path: comodo, Enabled: true, Active: true},
		cPanelRuleAgeVendor{ID: "OWASP3", Path: owasp, Enabled: true, Active: true},
	)

	age := checkRuleAge(cPanelRuleAgeInfo(), []string{stale, fresh})
	if age < 39 || age > 41 {
		t.Errorf("age = %d, want stale active vendor age (~40 days)", age)
	}
}

func TestCheckRuleAgeUsesNewestArtifactWithinActiveVendor(t *testing.T) {
	root := t.TempDir()
	vendor := wafVendorDir(t, root, "OWASP3", 90*24*time.Hour)
	fresh := filepath.Join(vendor, "RESPONSE-980-CORRELATION.conf")
	if err := os.WriteFile(fresh, []byte("SecRule ..."), 0o644); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-time.Hour)
	if err := os.Chtimes(fresh, when, when); err != nil {
		t.Fatal(err)
	}
	withCPanelRuleAgeVendors(t, cPanelRuleAgeVendor{
		ID: "OWASP3", Path: vendor, Enabled: true, Active: true,
	})

	if age := checkRuleAge(cPanelRuleAgeInfo(), []string{root}); age != 0 {
		t.Errorf("age = %d, want vendor refresh inferred from its newest artifact", age)
	}
}

func TestCheckRuleAgeDoesNotLetFreshActiveVendorHideStaleActiveVendor(t *testing.T) {
	root := t.TempDir()
	stale := wafVendorDir(t, root, "stale", 45*24*time.Hour)
	fresh := wafVendorDir(t, root, "fresh", time.Hour)
	withCPanelRuleAgeVendors(t,
		cPanelRuleAgeVendor{ID: "stale", Path: stale, Enabled: true, Active: true},
		cPanelRuleAgeVendor{ID: "fresh", Path: fresh, Enabled: true, Active: true},
	)

	age := checkRuleAge(cPanelRuleAgeInfo(), []string{root})
	if age < 44 || age > 46 {
		t.Errorf("age = %d, want stale active vendor age (~45 days)", age)
	}
}

func TestCheckRuleAgeDoesNotLetInactiveFreshVendorHideStaleActiveVendor(t *testing.T) {
	root := t.TempDir()
	active := wafVendorDir(t, root, "active", 45*24*time.Hour)
	inactive := wafVendorDir(t, root, "inactive", time.Hour)
	withCPanelRuleAgeVendors(t,
		cPanelRuleAgeVendor{ID: "active", Path: active, Enabled: true, Active: true},
		cPanelRuleAgeVendor{ID: "inactive", Path: inactive, Enabled: true},
	)

	age := checkRuleAge(cPanelRuleAgeInfo(), []string{root})
	if age < 44 || age > 46 {
		t.Errorf("age = %d, want stale active vendor age (~45 days)", age)
	}
}

func TestCheckRuleAgeUsesActiveConfigsOverVendorEnabledState(t *testing.T) {
	root := t.TempDir()
	loaded := wafVendorDir(t, root, "loaded", 45*24*time.Hour)
	notLoaded := wafVendorDir(t, root, "not-loaded", time.Hour)
	withCPanelRuleAgeVendors(t,
		cPanelRuleAgeVendor{ID: "loaded", Path: loaded, Active: true},
		cPanelRuleAgeVendor{ID: "not-loaded", Path: notLoaded, Enabled: true},
	)

	age := checkRuleAge(cPanelRuleAgeInfo(), []string{root})
	if age < 44 || age > 46 {
		t.Errorf("age = %d, want the disabled vendor's active config age (~45 days)", age)
	}
}

func TestCheckRuleAgeKeepsConservativeSemanticsWithoutActiveVendorAPI(t *testing.T) {
	stale := t.TempDir()
	fresh := t.TempDir()
	wafVendorDir(t, stale, "loaded", 45*24*time.Hour)
	wafVendorDir(t, fresh, "not-loaded", time.Hour)

	info := platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSApache}
	age := checkRuleAge(info, []string{stale, fresh})
	if age < 44 || age > 46 {
		t.Errorf("age = %d, want oldest candidate age (~45 days)", age)
	}
}

func TestCheckRuleAgeFallsBackConservativelyWhenCPanelAPIFails(t *testing.T) {
	root := t.TempDir()
	wafVendorDir(t, root, "loaded", 45*24*time.Hour)
	wafVendorDir(t, root, "not-loaded", time.Hour)
	withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) {
		return nil, fmt.Errorf("WHM API unavailable")
	}})

	age := checkRuleAge(cPanelRuleAgeInfo(), []string{root})
	if age < 44 || age > 46 {
		t.Errorf("age = %d, want conservative oldest age (~45 days)", age)
	}
}

func TestRuleArtifactScanRecursesIntoVendorRulesDirectory(t *testing.T) {
	root := t.TempDir()
	vendor := filepath.Join(root, "OWASP", "rules")
	if err := os.MkdirAll(vendor, 0o755); err != nil {
		t.Fatal(err)
	}
	rule := filepath.Join(vendor, "REQUEST-901-INITIALIZATION.conf")
	if err := os.WriteFile(rule, []byte("SecRule ..."), 0o644); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-45 * 24 * time.Hour)
	if err := os.Chtimes(rule, when, when); err != nil {
		t.Fatal(err)
	}

	if !hasRuleArtifacts([]string{root}) {
		t.Fatal("nested vendor rules must count as rule artifacts")
	}
	withCPanelRuleAgeVendors(t, cPanelRuleAgeVendor{
		ID: "OWASP", Path: filepath.Join(root, "OWASP"), Enabled: true, Active: true,
	})
	age := checkRuleAge(cPanelRuleAgeInfo(), []string{root})
	if age < 44 || age > 46 {
		t.Errorf("age = %d, want nested active vendor age (~45 days)", age)
	}
}
