//go:build linux && bpf

package daemon

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/processctx"
)

func TestAncestryCacheConcurrentPublication(t *testing.T) {
	oldCache := ancestryCache.Load()
	t.Cleanup(func() { ancestryCache.Store(oldCache) })
	cache := processctx.NewCache(8, time.Minute)
	cache.PutFromExec(987655, 1, 0, "rpm", "/usr/bin/rpm")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			wireAncestryCache(cache)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			if probe := cachedAncestryEvidence; probe != nil {
				probe(987655, nil)
			}
		}
	}()
	wg.Wait()
	if ev := cachedAncestryEvidence(987655, nil); !ev.packageManager {
		t.Fatal("published cache lost package-manager evidence")
	}
}

func TestCachedPanelAncestryRequiresResolvedExe(t *testing.T) {
	oldCache := ancestryCache.Load()
	t.Cleanup(func() { ancestryCache.Store(oldCache) })
	cache := processctx.NewCache(8, time.Minute)
	wireAncestryCache(cache)
	const pid = 987654
	const exe = "/usr/local/cpanel/bin/tool"
	overrideExeStat(t, map[string]struct {
		mode os.FileMode
		uid  uint32
	}{exe: {mode: 0o755, uid: 0}})

	// sched_process_exec's filename is the requested pathname, including
	// symlinks and scripts. Only a procfs read proves the running executable.
	cache.PutFromExec(pid, 1, 0, "tool", exe)
	if ev := cachedAncestryEvidence(pid, cpanelRoots); ev.panelTool {
		t.Error("unresolved exec-event filename was trusted as panel ancestry")
	}
	cache.PutFromProc(pid, 1, 0, "", "", "tool", exe, nil)
	if ev := cachedAncestryEvidence(pid, cpanelRoots); !ev.panelTool {
		t.Error("resolved executable must retain cached panel ancestry")
	}
	cache.PutFromExec(pid, 1, 0, "tool", exe)
	if ev := cachedAncestryEvidence(pid, cpanelRoots); ev.panelTool {
		t.Error("a new exec must invalidate the previous resolved executable")
	}
	cache.PutFromProc(pid, 1, 0, "", "", "tool", "/usr/bin/sh", []string{exe})
	if ev := cachedAncestryEvidence(pid, cpanelRoots); ev.panelTool {
		t.Error("script argument must not substitute for the resolved executable")
	}
}

func TestCachedPanelAncestryAvoidsProcWalk(t *testing.T) {
	oldCache := ancestryCache.Load()
	t.Cleanup(func() { ancestryCache.Store(oldCache) })
	cache := processctx.NewCache(8, time.Minute)
	wireAncestryCache(cache)
	const pid = 987656
	const exe = "/usr/local/cpanel/bin/tool"
	root := fakeProc(t, map[int32]struct {
		comm string
		ppid int32
	}{pid: {comm: "tool", ppid: 1}})
	overrideProcRoot(t, root)
	overridePanelToolRoots(t, cpanelRoots)
	writeProcExe(t, root, pid, exe)

	oldStat := exeStat
	t.Cleanup(func() { exeStat = oldStat })
	calls := 0
	exeStat = func(string) (os.FileMode, uint32, error) {
		calls++
		return 0o755, 0, nil
	}
	cache.PutFromProc(pid, 1, 0, "", "", "tool", exe, nil)
	if ev := ancestryEvidenceFor(pid); !ev.panelTool || calls != 1 {
		t.Fatalf("cached proof must avoid a second stat through procfs: evidence=%+v calls=%d", ev, calls)
	}

	// An unresolved cache entry proves nothing; the live resolved link can.
	cache.PutFromExec(pid, 1, 0, "tool", exe)
	calls = 0
	if ev := ancestryEvidenceFor(pid); !ev.panelTool || calls != 1 {
		t.Fatalf("unresolved cache must fall back to procfs: evidence=%+v calls=%d", ev, calls)
	}
}
