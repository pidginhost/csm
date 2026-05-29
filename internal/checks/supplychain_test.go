package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestSemverCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.3.0", "1.2.9", 1},
		{"2.0.0", "1.99.99", 1},
		{"v1.0.0", "1.0.0", 0},
		{"V1.0.0", "1.0.0", 0},
		{"1.2.3-beta", "1.2.3", 0}, // pre-release suffix ignored
		{"1.2.3+build1", "1.2.3", 0},
		{"1.2", "1.2.0", 0},
		{"1.10.0", "1.9.0", 1}, // numeric, not lexical
	}
	for _, c := range cases {
		if got := semverCompare(c.a, c.b); got != c.want {
			t.Errorf("semverCompare(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionVulnerable(t *testing.T) {
	ranges := []supplyChainAdvisoryRange{{Introduced: "1.0.0", Fixed: "1.2.4"}}
	if !versionVulnerable("1.2.3", ranges) {
		t.Error("1.2.3 in [1.0.0,1.2.4) should be vulnerable")
	}
	if versionVulnerable("1.2.4", ranges) {
		t.Error("1.2.4 == fixed should NOT be vulnerable")
	}
	if versionVulnerable("0.9.0", ranges) {
		t.Error("0.9.0 below introduced should NOT be vulnerable")
	}
	// No fixed version: everything from introduced up is vulnerable.
	openRange := []supplyChainAdvisoryRange{{Introduced: "0", Fixed: ""}}
	if !versionVulnerable("9.9.9", openRange) {
		t.Error("any version should be vulnerable when introduced=0 and no fix")
	}
}

func TestParseComposerLock(t *testing.T) {
	data := []byte(`{"packages":[{"name":"monolog/monolog","version":"2.1.0"}],` +
		`"packages-dev":[{"name":"phpunit/phpunit","version":"v9.5.0"}]}`)
	pkgs := parseComposerLock(data)
	if len(pkgs) != 2 {
		t.Fatalf("parsed %d packages, want 2: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Ecosystem != "composer" || pkgs[0].Name != "monolog/monolog" || pkgs[0].Version != "2.1.0" {
		t.Errorf("pkg[0] = %+v", pkgs[0])
	}
}

func TestParsePackageLockV3(t *testing.T) {
	data := []byte(`{"packages":{` +
		`"":{"version":"1.0.0"},` +
		`"node_modules/lodash":{"version":"4.17.20"},` +
		`"node_modules/@scope/pkg":{"version":"3.1.0"},` +
		`"node_modules/a/node_modules/b":{"version":"2.0.0"},` +
		`"node_modules/a/node_modules/@scope/nested":{"version":"5.0.0"}}}`)
	pkgs := parsePackageLock(data)
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	if got["lodash"] != "4.17.20" {
		t.Errorf("lodash version = %q", got["lodash"])
	}
	if got["b"] != "2.0.0" {
		t.Errorf("nested package b version = %q", got["b"])
	}
	if got["@scope/pkg"] != "3.1.0" {
		t.Errorf("scoped package version = %q", got["@scope/pkg"])
	}
	if got["@scope/nested"] != "5.0.0" {
		t.Errorf("nested scoped package version = %q", got["@scope/nested"])
	}
	if _, ok := got[""]; ok {
		t.Error("root project entry must not be reported as a package")
	}
}

func TestParsePackageLockV1Fallback(t *testing.T) {
	data := []byte(`{"dependencies":{"lodash":{"version":"4.17.20",` +
		`"dependencies":{"debug":{"version":"2.6.8"},` +
		`"@scope/pkg":{"version":"1.0.0"}}}}}`)
	pkgs := parsePackageLock(data)
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	if len(got) != 3 {
		t.Fatalf("parsed v1 dependencies = %+v, want 3 packages", pkgs)
	}
	if got["lodash"] != "4.17.20" {
		t.Errorf("lodash version = %q", got["lodash"])
	}
	if got["debug"] != "2.6.8" {
		t.Errorf("nested debug version = %q", got["debug"])
	}
	if got["@scope/pkg"] != "1.0.0" {
		t.Errorf("nested scoped package version = %q", got["@scope/pkg"])
	}
}

func TestIndexAndFindingSeverity(t *testing.T) {
	advs := []supplyChainAdvisory{
		{Ecosystem: "composer", Package: "monolog/monolog", ID: "CVE-X", Severity: "critical",
			Ranges: []supplyChainAdvisoryRange{{Introduced: "0", Fixed: "2.2.0"}}},
	}
	idx := indexAdvisories(advs)
	hits := idx[advisoryKey("composer", "monolog/monolog")]
	if len(hits) != 1 {
		t.Fatalf("index miss: %+v", idx)
	}
	lockPath := "/home/alice/public_html/composer.lock"
	f := supplyChainFinding("alice", lockPath, supplyChainPkg{Ecosystem: "composer", Name: "monolog/monolog", Version: "2.1.0"}, hits[0])
	if f.Check != "supply_chain_vuln" {
		t.Errorf("check = %q", f.Check)
	}
	if f.Severity.String() != "CRITICAL" {
		t.Errorf("severity = %s, want CRITICAL", f.Severity)
	}
	if f.FilePath != lockPath {
		t.Errorf("file path = %q, want %q", f.FilePath, lockPath)
	}
}

func TestCheckSupplyChainDormantWithoutAdvisories(t *testing.T) {
	// Point state at a temp dir with no advisory file: the check must be
	// a silent no-op rather than erroring.
	old := osFS
	osFS = realOS{}
	t.Cleanup(func() { osFS = old })

	cfg := &config.Config{StatePath: t.TempDir()}
	if got := CheckSupplyChain(context.Background(), cfg, nil); got != nil {
		t.Errorf("dormant check returned %d findings, want nil", len(got))
	}
}

func TestCheckSupplyChainAcceptsNilContext(t *testing.T) {
	old := osFS
	osFS = &mockOS{
		readFile: func(name string) ([]byte, error) {
			if filepath.Base(name) == "supply-chain.json" {
				return []byte(`{"advisories":[{"ecosystem":"npm","package":"lodash",` +
					`"ranges":[{"introduced":"0","fixed":"4.17.21"}],"id":"CVE-X","severity":"high"}]}`), nil
			}
			return []byte(`{"dependencies":{"lodash":{"version":"4.17.20"}}}`), nil
		},
		glob: func(pattern string) ([]string, error) {
			if filepath.Base(pattern) == "package-lock.json" {
				return []string{"/home/alice/package-lock.json"}, nil
			}
			return nil, nil
		},
	}
	t.Cleanup(func() { osFS = old })

	findings := CheckSupplyChain(nil, &config.Config{StatePath: "/state"}, nil) //nolint:staticcheck // SA1012: check entrypoint accepts nil context.
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one supply-chain finding", findings)
	}
}

func TestCheckSupplyChainReadsDuplicateGlobMatchOnce(t *testing.T) {
	old := osFS
	lockPath := "/home/alice/package-lock.json"
	lockReads := 0
	osFS = &mockOS{
		readFile: func(name string) ([]byte, error) {
			if filepath.Base(name) == "supply-chain.json" {
				return []byte(`{"advisories":[{"ecosystem":"npm","package":"lodash",` +
					`"ranges":[{"introduced":"0","fixed":"4.17.21"}],"id":"CVE-X","severity":"high"}]}`), nil
			}
			if name == lockPath {
				lockReads++
				return []byte(`{"dependencies":{"lodash":{"version":"4.17.20"}}}`), nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			if filepath.Base(pattern) == "package-lock.json" {
				return []string{lockPath}, nil
			}
			return nil, nil
		},
	}
	t.Cleanup(func() { osFS = old })

	findings := CheckSupplyChain(context.Background(), &config.Config{StatePath: "/state"}, nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one supply-chain finding", findings)
	}
	if lockReads != 1 {
		t.Fatalf("lockfile reads = %d, want 1", lockReads)
	}
}

func TestLoadSupplyChainAdvisories(t *testing.T) {
	old := osFS
	osFS = realOS{}
	t.Cleanup(func() { osFS = old })

	dir := t.TempDir()
	advDir := filepath.Join(dir, "advisories")
	if err := os.MkdirAll(advDir, 0700); err != nil {
		t.Fatal(err)
	}
	body := `{"advisories":[{"ecosystem":"npm","package":"lodash",` +
		`"ranges":[{"introduced":"0","fixed":"4.17.21"}],"id":"CVE-2021-23337","severity":"high"}]}`
	if err := os.WriteFile(filepath.Join(advDir, "supply-chain.json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	advs := loadSupplyChainAdvisories(dir)
	if len(advs) != 1 || advs[0].Package != "lodash" {
		t.Fatalf("loaded advisories = %+v", advs)
	}
}
