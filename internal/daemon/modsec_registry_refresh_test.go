package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/modsec"
)

// The refresh ran full platform detection and reparsed every vendor rule file
// every five minutes. Detection forks one process per candidate web-server
// unit, and the rule tree changes on the order of a vendor pack update, so the
// steady state was pure waste. It still has to keep probing while detection
// has not produced a usable rule set - that is the boot-order case it exists
// for.

type modsecRefreshProbe struct {
	dirs   []string
	probes int
	builds int
}

func (p *modsecRefreshProbe) install(t *testing.T) {
	t.Helper()
	previousProbe, previousBuild := modsecProbeRuleDirs, modsecBuildRegistry
	t.Cleanup(func() { modsecProbeRuleDirs, modsecBuildRegistry = previousProbe, previousBuild })
	modsecProbeRuleDirs = func() []string {
		p.probes++
		return p.dirs
	}
	modsecBuildRegistry = func(dirs []string) (*modsec.Registry, error) {
		p.builds++
		return modsec.BuildRegistry(dirs)
	}
}

func modsecRuleDir(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vendor.conf"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

const modsecTestRule = `SecRule ARGS "@rx evil" "id:210710,phase:2,pass,log"`

func TestModSecRefreshStopsProbingAndRebuildingOnceRulesLoad(t *testing.T) {
	installModSecRegistryForTest(t, map[int]string{1: "deny"})
	probe := &modsecRefreshProbe{dirs: []string{modsecRuleDir(t, modsecTestRule)}}
	probe.install(t)
	d := &Daemon{}

	d.refreshModSecRegistry()
	if probe.probes != 1 || probe.builds != 1 {
		t.Fatalf("first refresh: probes=%d builds=%d, want 1 and 1", probe.probes, probe.builds)
	}

	d.refreshModSecRegistry()
	d.refreshModSecRegistry()

	if probe.probes != 1 {
		t.Errorf("platform was probed %d times after a healthy registry loaded, want 1", probe.probes)
	}
	if probe.builds != 1 {
		t.Errorf("rule tree was parsed %d times without changing, want 1", probe.builds)
	}
	if got := modsec.Global(); got == nil || got.Len() == 0 {
		t.Fatal("refresh did not install the rules it parsed")
	}
}

func TestModSecRefreshKeepsProbingWhileNoRulesLoad(t *testing.T) {
	installModSecRegistryForTest(t, map[int]string{1: "deny"})
	probe := &modsecRefreshProbe{dirs: []string{t.TempDir()}}
	probe.install(t)
	d := &Daemon{}

	d.refreshModSecRegistry()
	d.refreshModSecRegistry()

	if probe.probes != 2 {
		t.Fatalf("platform was probed %d times while the rule set stayed empty, want one per refresh", probe.probes)
	}
}

func TestModSecRefreshRebuildsWhenTheRuleTreeChanges(t *testing.T) {
	installModSecRegistryForTest(t, map[int]string{1: "deny"})
	dir := modsecRuleDir(t, modsecTestRule)
	probe := &modsecRefreshProbe{dirs: []string{dir}}
	probe.install(t)
	d := &Daemon{}
	d.refreshModSecRegistry()

	if err := os.WriteFile(filepath.Join(dir, "extra.conf"),
		[]byte(`SecRule ARGS "@rx worse" "id:214930,phase:2,deny"`), 0o644); err != nil {
		t.Fatal(err)
	}
	d.refreshModSecRegistry()

	if probe.builds != 2 {
		t.Fatalf("rule tree parsed %d times across a vendor pack change, want 2", probe.builds)
	}
	if got := modsec.Global(); got == nil || got.Len() != 2 {
		t.Fatalf("registry did not pick up the added rule: %v", got)
	}
}

func TestModSecRefreshProbesAgainWhenTheRuleDirsDisappear(t *testing.T) {
	installModSecRegistryForTest(t, map[int]string{1: "deny"})
	dir := modsecRuleDir(t, modsecTestRule)
	probe := &modsecRefreshProbe{dirs: []string{dir}}
	probe.install(t)
	d := &Daemon{}
	d.refreshModSecRegistry()

	// The web server was swapped out, or the vendor pack removed: the
	// directories the last detection resolved are gone.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	probe.dirs = []string{modsecRuleDir(t, strings.ReplaceAll(modsecTestRule, "pass", "deny"))}
	d.refreshModSecRegistry()
	d.refreshModSecRegistry()

	if probe.probes != 2 || probe.builds != 2 {
		t.Fatalf("replacement tree was not cached: probes=%d builds=%d, want 2 and 2", probe.probes, probe.builds)
	}
	if action, _ := modsec.Global().Action(210710); action != "deny" {
		t.Fatalf("disappearing directories did not trigger replacement rules: action=%q", action)
	}
}

func TestModSecRefreshRecoversFromEmptyStartup(t *testing.T) {
	previous := modsec.Global()
	modsec.SetGlobal(nil)
	t.Cleanup(func() { modsec.SetGlobal(previous) })
	probe := &modsecRefreshProbe{dirs: []string{t.TempDir()}}
	probe.install(t)
	d := &Daemon{}
	d.refreshModSecRegistry()

	probe.dirs = []string{modsecRuleDir(t, modsecTestRule)}
	d.refreshModSecRegistry()
	if probe.probes != 2 {
		t.Errorf("empty startup stopped platform detection: probes=%d", probe.probes)
	}
	if action, _ := modsec.Global().Action(210710); action != "pass" {
		t.Fatalf("boot-time misdetect did not self-heal: action=%q", action)
	}
}

func TestModSecRefreshRecoversWhenRulesDisappearButDirectoryRemains(t *testing.T) {
	installModSecRegistryForTest(t, map[int]string{1: "deny"})
	dir := modsecRuleDir(t, modsecTestRule)
	probe := &modsecRefreshProbe{dirs: []string{dir}}
	probe.install(t)
	d := &Daemon{}
	d.refreshModSecRegistry()
	if err := os.Remove(filepath.Join(dir, "vendor.conf")); err != nil {
		t.Fatal(err)
	}
	d.refreshModSecRegistry()
	if action, _ := modsec.Global().Action(210710); action != "pass" {
		t.Fatal("empty tree discarded the last healthy registry")
	}
	probe.dirs = []string{modsecRuleDir(t, strings.ReplaceAll(modsecTestRule, "pass", "deny"))}
	d.refreshModSecRegistry()
	if action, _ := modsec.Global().Action(210710); action != "deny" {
		t.Fatalf("refresh did not discover the replacement rule tree: action=%q", action)
	}
}

func TestModSecRefreshRebuildsAfterMetadataPreservingReplacement(t *testing.T) {
	installModSecRegistryForTest(t, map[int]string{1: "deny"})
	dir := modsecRuleDir(t, modsecTestRule)
	path := filepath.Join(dir, "vendor.conf")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	probe := &modsecRefreshProbe{dirs: []string{dir}}
	probe.install(t)
	d := &Daemon{}
	d.refreshModSecRegistry()
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(modsecTestRule, "pass", "deny")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	d.refreshModSecRegistry()
	if action, _ := modsec.Global().Action(210710); action != "deny" {
		t.Fatalf("registry retained outdated action %q", action)
	}
	if probe.probes != 1 || probe.builds != 2 {
		t.Fatalf("refresh: probes=%d builds=%d, want 1 and 2", probe.probes, probe.builds)
	}
}

// A build that could not read every rule file describes an unknown tree, so
// it must not be cached: the next refresh has to look again, and only a build
// that read everything ends the retries.
func TestModSecRefreshRetriesIncompleteBuild(t *testing.T) {
	installModSecRegistryForTest(t, map[int]string{1: "deny"})
	dir := modsecRuleDir(t, modsecTestRule)
	broken := filepath.Join(dir, "broken.conf")
	if err := os.Symlink(filepath.Join(dir, "absent"), broken); err != nil {
		t.Fatal(err)
	}
	probe := &modsecRefreshProbe{dirs: []string{dir}}
	probe.install(t)
	d := &Daemon{}

	d.refreshModSecRegistry()
	d.refreshModSecRegistry()
	if probe.builds != 2 {
		t.Fatalf("incomplete build was cached: builds=%d, want one per refresh", probe.builds)
	}

	if err := os.Remove(broken); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(broken, []byte(strings.ReplaceAll(modsecTestRule, "210710", "214930")), 0o644); err != nil {
		t.Fatal(err)
	}
	d.refreshModSecRegistry()
	d.refreshModSecRegistry()
	if probe.builds != 3 {
		t.Fatalf("complete build was not cached: builds=%d, want 3", probe.builds)
	}
	if action, _ := modsec.Global().Action(214930); action != "pass" {
		t.Fatalf("recovered file's rules were not loaded: action=%q", action)
	}
}

func TestModSecRefreshDoesNotCacheRulesFromATransientRewrite(t *testing.T) {
	installModSecRegistryForTest(t, map[int]string{1: "deny"})
	dir := modsecRuleDir(t, modsecTestRule)
	path := filepath.Join(dir, "vendor.conf")
	probe := &modsecRefreshProbe{dirs: []string{dir}}
	probe.install(t)
	build := modsecBuildRegistry
	modsecBuildRegistry = func(dirs []string) (*modsec.Registry, error) {
		if probe.builds != 0 {
			return build(dirs)
		}
		// A vendor rewrite starts after fingerprinting, then rolls back
		// after parsing. The cache key must describe the bytes parsed.
		if err := os.WriteFile(path, []byte(strings.ReplaceAll(modsecTestRule, "pass", "deny")), 0o644); err != nil {
			t.Fatal(err)
		}
		reg, err := build(dirs)
		if restoreErr := os.WriteFile(path, []byte(modsecTestRule), 0o644); restoreErr != nil {
			t.Fatal(restoreErr)
		}
		return reg, err
	}
	d := &Daemon{}
	d.refreshModSecRegistry()
	d.refreshModSecRegistry()
	if action, _ := modsec.Global().Action(210710); action != "pass" {
		t.Fatalf("transient contents were cached against the restored file: action=%q", action)
	}
	if probe.builds != 2 {
		t.Fatalf("transient rewrite must rebuild once: builds=%d", probe.builds)
	}
}

// A vendor file the parser cannot read to the end -- past the line ceiling,
// truncated mid-rule -- is stable content. Rebuilding it every five minutes
// produces the same registry and the same error, so it must not defeat the
// cache the way an unread file does.
func TestModSecRefreshCachesDespiteAnUnparseableRuleFile(t *testing.T) {
	installModSecRegistryForTest(t, map[int]string{1: "deny"})
	dir := modsecRuleDir(t, modsecTestRule)
	body := `SecRule ARGS "@rx ` + strings.Repeat("A", 9<<20) + `" "id:99,deny"`
	if err := os.WriteFile(filepath.Join(dir, "oversized.conf"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	probe := &modsecRefreshProbe{dirs: []string{dir}}
	probe.install(t)
	d := &Daemon{}

	d.refreshModSecRegistry()
	d.refreshModSecRegistry()

	if probe.builds != 1 {
		t.Fatalf("rule tree parsed %d times with a stable unparseable file, want 1", probe.builds)
	}
	if action, _ := modsec.Global().Action(210710); action != "pass" {
		t.Fatalf("rules from the readable files were lost: action=%q", action)
	}
}
