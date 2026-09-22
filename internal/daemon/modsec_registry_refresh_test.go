package daemon

import (
	"os"
	"path/filepath"
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
	d.refreshModSecRegistry()

	if probe.probes != 2 {
		t.Fatalf("platform was probed %d times after its rule directories vanished, want 2", probe.probes)
	}
}
