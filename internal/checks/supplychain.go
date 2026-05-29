package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// Supply-chain dependency scanning.
//
// This is the scanner half of the supply-chain check: it parses
// composer.lock / package-lock.json dependency trees under customer
// document roots and matches the resolved versions against a local
// advisory database. The advisory database itself is operational data,
// not shipped in the binary -- an operator or a sync job writes
// <state>/advisories/supply-chain.json (format documented in
// docs/supply-chain-advisories.md). With no advisory file present the
// check is dormant: it parses nothing it cannot match and emits nothing.
// This mirrors the YARA-forge mirror posture (machinery in CSM, signed
// data delivered out of band).

// supplyChainAdvisoryRelPath is where CSM looks for the advisory DB,
// relative to the configured state directory.
const supplyChainAdvisoryRelPath = "advisories/supply-chain.json"

// supplyChainPkg is one resolved dependency from a lockfile.
type supplyChainPkg struct {
	Ecosystem string // "composer" | "npm"
	Name      string
	Version   string
}

// supplyChainAdvisory is the OSV-subset advisory shape CSM matches
// against. A version is vulnerable when it falls inside any range:
// version >= introduced AND (fixed == "" OR version < fixed).
type supplyChainAdvisory struct {
	Ecosystem string                     `json:"ecosystem"`
	Package   string                     `json:"package"`
	Ranges    []supplyChainAdvisoryRange `json:"ranges"`
	ID        string                     `json:"id"`
	Severity  string                     `json:"severity"`
	Summary   string                     `json:"summary"`
}

type supplyChainAdvisoryRange struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

type supplyChainAdvisoryFile struct {
	Advisories []supplyChainAdvisory `json:"advisories"`
}

// CheckSupplyChain scans customer dependency lockfiles for versions with
// known advisories. Dormant unless an advisory database is present at
// <state>/advisories/supply-chain.json.
func CheckSupplyChain(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if cfg == nil {
		return nil
	}
	advisories := loadSupplyChainAdvisories(cfg.StatePath)
	if len(advisories) == 0 {
		return nil // no data -> nothing to match against
	}
	index := indexAdvisories(advisories)

	var findings []alert.Finding
	for _, lock := range discoverLockfiles(ctx) {
		if ctx != nil && ctx.Err() != nil {
			return findings
		}
		data, err := osFS.ReadFile(lock.path)
		if err != nil {
			continue
		}
		pkgs := lock.parse(data)
		for _, p := range pkgs {
			for _, adv := range index[advisoryKey(p.Ecosystem, p.Name)] {
				if versionVulnerable(p.Version, adv.Ranges) {
					findings = append(findings, supplyChainFinding(lock.account, lock.path, p, adv))
				}
			}
		}
	}
	return findings
}

func loadSupplyChainAdvisories(statePath string) []supplyChainAdvisory {
	if statePath == "" {
		return nil
	}
	data, err := osFS.ReadFile(filepath.Join(statePath, supplyChainAdvisoryRelPath))
	if err != nil {
		return nil
	}
	var f supplyChainAdvisoryFile
	if json.Unmarshal(data, &f) != nil {
		return nil
	}
	return f.Advisories
}

func advisoryKey(ecosystem, pkg string) string {
	return strings.ToLower(ecosystem) + "\x00" + strings.ToLower(pkg)
}

func indexAdvisories(advisories []supplyChainAdvisory) map[string][]supplyChainAdvisory {
	out := map[string][]supplyChainAdvisory{}
	for _, a := range advisories {
		if a.Package == "" || a.Ecosystem == "" {
			continue
		}
		k := advisoryKey(a.Ecosystem, a.Package)
		out[k] = append(out[k], a)
	}
	return out
}

type lockfile struct {
	path    string
	account string
	parse   func([]byte) []supplyChainPkg
}

type packageLockDependency struct {
	Version      string                           `json:"version"`
	Dependencies map[string]packageLockDependency `json:"dependencies"`
}

// discoverLockfiles globs composer.lock and package-lock.json at the
// common project depths under customer home directories. Bounded by the
// glob shape (no recursive walk) so a deep node_modules tree cannot turn
// the scan into an unbounded crawl.
func discoverLockfiles(ctx context.Context) []lockfile {
	patterns := []struct {
		glob  string
		parse func([]byte) []supplyChainPkg
	}{
		{"/home/*/public_html/composer.lock", parseComposerLock},
		{"/home/*/composer.lock", parseComposerLock},
		{"/home/*/public_html/package-lock.json", parsePackageLock},
		{"/home/*/package-lock.json", parsePackageLock},
	}
	var out []lockfile
	seen := map[string]struct{}{}
	for _, p := range patterns {
		if ctx != nil && ctx.Err() != nil {
			return out
		}
		matches, _ := osFS.Glob(p.glob)
		for _, m := range matches {
			if _, dup := seen[m]; dup {
				continue
			}
			seen[m] = struct{}{}
			out = append(out, lockfile{path: m, account: extractUser(m), parse: p.parse})
		}
	}
	return out
}

func parseComposerLock(data []byte) []supplyChainPkg {
	var doc struct {
		Packages    []struct{ Name, Version string } `json:"packages"`
		PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []supplyChainPkg
	for _, set := range [][]struct{ Name, Version string }{doc.Packages, doc.PackagesDev} {
		for _, p := range set {
			if p.Name == "" || p.Version == "" {
				continue
			}
			out = append(out, supplyChainPkg{Ecosystem: "composer", Name: p.Name, Version: p.Version})
		}
	}
	return out
}

func parsePackageLock(data []byte) []supplyChainPkg {
	var doc struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]packageLockDependency `json:"dependencies"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []supplyChainPkg
	// npm v2/v3: keyed by "node_modules/<name>" (the root "" entry is the
	// project itself and has no node_modules prefix).
	paths := make([]string, 0, len(doc.Packages))
	for path := range doc.Packages {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		v := doc.Packages[path]
		name := npmNameFromPackagesKey(path)
		if name == "" || v.Version == "" {
			continue
		}
		out = append(out, supplyChainPkg{Ecosystem: "npm", Name: name, Version: v.Version})
	}
	// npm v1: dependency tree rooted at the top-level dependencies map.
	if len(doc.Packages) == 0 {
		return appendPackageLockV1Dependencies(out, doc.Dependencies)
	}
	return out
}

func appendPackageLockV1Dependencies(out []supplyChainPkg, deps map[string]packageLockDependency) []supplyChainPkg {
	stack := []map[string]packageLockDependency{deps}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		names := make([]string, 0, len(cur))
		for name := range cur {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			dep := cur[name]
			if name != "" && dep.Version != "" {
				out = append(out, supplyChainPkg{Ecosystem: "npm", Name: name, Version: dep.Version})
			}
			if len(dep.Dependencies) > 0 {
				stack = append(stack, dep.Dependencies)
			}
		}
	}
	return out
}

// npmNameFromPackagesKey extracts the package name from a v2/v3
// package-lock "packages" key. The key is the path "node_modules/<name>"
// (or nested "node_modules/a/node_modules/b"); the name is whatever
// follows the last "node_modules/". The root project key "" yields "".
func npmNameFromPackagesKey(key string) string {
	if key == "" {
		return ""
	}
	parts := strings.Split(key, "/")
	for i := len(parts) - 2; i >= 0; i-- {
		if parts[i] != "node_modules" {
			continue
		}
		if parts[i+1] == "" {
			return ""
		}
		if strings.HasPrefix(parts[i+1], "@") {
			if i+2 >= len(parts) || parts[i+2] == "" {
				return ""
			}
			return parts[i+1] + "/" + parts[i+2]
		}
		return parts[i+1]
	}
	return ""
}

// versionVulnerable reports whether version falls inside any advisory
// range: version >= introduced AND (fixed == "" OR version < fixed).
// An empty/"0" introduced means "from the beginning".
func versionVulnerable(version string, ranges []supplyChainAdvisoryRange) bool {
	for _, r := range ranges {
		introOK := r.Introduced == "" || r.Introduced == "0" || semverCompare(version, r.Introduced) >= 0
		fixedOK := r.Fixed == "" || semverCompare(version, r.Fixed) < 0
		if introOK && fixedOK {
			return true
		}
	}
	return false
}

// semverCompare compares two dotted versions numerically segment by
// segment, tolerating a leading "v" and ignoring any pre-release/build
// suffix after the first "-" or "+". Returns -1, 0, or 1. Non-numeric
// segments compare as 0 so a malformed version never panics.
func semverCompare(a, b string) int {
	as := semverSegments(a)
	bs := semverSegments(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func semverSegments(v string) []int {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out
}

func supplyChainFinding(account, lockPath string, p supplyChainPkg, adv supplyChainAdvisory) alert.Finding {
	sev := alert.High
	switch strings.ToLower(adv.Severity) {
	case "critical":
		sev = alert.Critical
	case "low", "medium", "moderate", "":
		sev = alert.Warning
	}
	id := adv.ID
	if id == "" {
		id = "advisory"
	}
	fixed := "no fixed version published"
	for _, r := range adv.Ranges {
		if r.Fixed != "" {
			fixed = "fixed in " + r.Fixed
			break
		}
	}
	return alert.Finding{
		Severity: sev,
		Check:    "supply_chain_vuln",
		Message: fmt.Sprintf("Vulnerable %s dependency %s %s (%s) on account %s",
			p.Ecosystem, p.Name, p.Version, id, account),
		Details: fmt.Sprintf("Account: %s\nLockfile: %s\nEcosystem: %s\nPackage: %s\nVersion: %s\nAdvisory: %s\nSeverity: %s\nFix: %s\n%s",
			account, lockPath, p.Ecosystem, p.Name, p.Version, id, adv.Severity, fixed, adv.Summary),
		FilePath:  lockPath,
		Timestamp: time.Now(),
	}
}
