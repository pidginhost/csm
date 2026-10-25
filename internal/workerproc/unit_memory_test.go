package workerproc

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// cgroupDir is where the fake puts unit's memory cgroup for its layout.
func (f *unitFake) cgroupDir(unit string) string {
	if strings.HasPrefix(f.layout, "v1") {
		return filepath.Join(f.cgroupRoot, "memory", "system.slice", unitSlice(f.prefix), unit+".service")
	}
	return filepath.Join(f.cgroupRoot, "system.slice", unitSlice(f.prefix), unit+".service")
}

// writeCgroup builds the fake /proc/<pid>/cgroup and cgroup files the way a
// unit started by systemd would see them.
func (f *unitFake) writeCgroup(pid int, unit string) error {
	path := "/system.slice/" + unitSlice(f.prefix) + "/" + unit + ".service"
	procFile := "0::" + path + "\n"
	if strings.HasPrefix(f.layout, "v1") {
		procFile = "7:memory:" + path + "\n" + procFile
	}
	procDir := filepath.Join(f.procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(procDir, "cgroup"), []byte(procFile), 0o644); err != nil {
		return err
	}
	if f.layout == "none" {
		return nil // The process names a cgroup that is not there.
	}
	dir := f.cgroupDir(unit)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if !strings.HasPrefix(f.layout, "v1") {
		// A slice survives worker replacements and keeps their kill count.
		events, err := os.OpenFile(filepath.Join(filepath.Dir(dir), "memory.events"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			_, err = events.WriteString("oom_kill 0\n")
			_ = events.Close()
		}
		if err != nil && !os.IsExist(err) {
			return err
		}
	}
	files := map[string]string{}
	switch f.layout {
	case "v2":
		files = map[string]string{"memory.current": "1048576", "memory.swap.current": "0", "memory.swap.max": "max"}
	case "v2-noswapacct":
		files = map[string]string{"memory.current": "1048576"}
	case "v1-memsw":
		files = map[string]string{"memory.usage_in_bytes": "1048576", "memory.memsw.usage_in_bytes": "1048576", "memory.memsw.limit_in_bytes": "9223372036854771712", "memory.swappiness": "60"}
	case "v1-noswap":
		files = map[string]string{"memory.usage_in_bytes": "1048576", "memory.swappiness": "60"}
	case "v1-uncappable":
		files = map[string]string{"memory.usage_in_bytes": "1048576", "memory.memsw.usage_in_bytes": "1048576"}
		if err := os.Mkdir(filepath.Join(dir, "memory.memsw.limit_in_bytes"), 0o755); err != nil {
			return err
		}
	}
	for name, value := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value+"\n"), 0o644); err != nil {
			return err
		}
	}
	ram := "memory.max"
	if strings.HasPrefix(f.layout, "v1") {
		ram = "memory.limit_in_bytes"
	}
	if err := os.WriteFile(filepath.Join(dir, ram), []byte("536870912\n"), 0o644); err != nil {
		return err
	}
	return nil
}

func readTrim(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func writeValue(t *testing.T, path, value string) {
	t.Helper()
	// Unlike regular files, cgroup counters cannot be read mid-truncate.
	if err := os.WriteFile(path+".tmp", []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}

func TestFindMemoryCgroupPrefersV1MemoryLine(t *testing.T) {
	proc, root := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "42"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeValue(t, filepath.Join(proc, "42", "cgroup"), "11:cpu,cpuacct:/system.slice/u.service\n7:memory:/system.slice/u.service\n0::/system.slice/u.service\n")
	for _, dir := range []string{"memory/system.slice/u.service", "system.slice/u.service"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cg, found, err := findMemoryCgroup(proc, root, 42, "u")
	if err != nil || !found || cg.v2 || cg.dir != filepath.Join(root, "memory/system.slice/u.service") {
		t.Fatalf("cgroup = %+v found=%v err=%v", cg, found, err)
	}
}

func TestUnitLauncherCapsV1MemSwap(t *testing.T) {
	cfg, f := fakeUnitConfig(t, "1")
	f.layout = "v1-memsw"
	p := launchUnit(t, cfg)
	if got := readTrim(t, filepath.Join(f.cgroupDir(p.unit), "memory.memsw.limit_in_bytes")); got != "536870912" {
		t.Fatalf("memsw limit = %s", got)
	}
}

func TestUnitLauncherSwappinessWithoutSwapAccounting(t *testing.T) {
	cfg, f := fakeUnitConfig(t, "1")
	f.layout = "v1-noswap"
	p := launchUnit(t, cfg)
	if got := readTrim(t, filepath.Join(f.cgroupDir(p.unit), "memory.swappiness")); got != "0" {
		t.Fatalf("swappiness = %s", got)
	}
}

func TestUnitLauncherV2SwapMax(t *testing.T) {
	cfg, f := fakeUnitConfig(t, "1")
	p := launchUnit(t, cfg)
	if got := readTrim(t, filepath.Join(f.cgroupDir(p.unit), "memory.swap.max")); got != "0" {
		t.Fatalf("swap.max = %s", got)
	}
}

func TestUnitLauncherRefusesUncappableWorker(t *testing.T) {
	cfg, f := fakeUnitConfig(t, "1")
	f.layout = "v1-uncappable"
	_, err := UnitLauncher(cfg)(context.Background())
	if err == nil || !strings.Contains(err.Error(), "isolation unavailable") {
		t.Fatalf("launch = %v", err)
	}
	p := f.waitKills(t, 1)[0]
	select {
	case <-p.Done():
	case <-time.After(reapTimeout):
		t.Fatal("uncappable unit not reaped")
	}
}

func TestUnitLauncherRefusesWorkerWithoutMemoryCgroup(t *testing.T) {
	cfg, f := fakeUnitConfig(t, "1")
	f.layout = "none"
	if _, err := UnitLauncher(cfg)(context.Background()); err == nil || !strings.Contains(err.Error(), "cannot cap worker memory") {
		t.Fatalf("launch = %v", err)
	}
	f.waitKills(t, 1)
}

// Without swap accounting, cgroup v2 cannot charge swap to the unit, so a
// worker over memory.max swaps instead of dying. That is only safe on a host
// with no swap.
func TestUnitLauncherV2WithoutSwapAccounting(t *testing.T) {
	for _, tc := range []struct {
		swaps string
		ok    bool
	}{
		{swaps: "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n", ok: true},
		{swaps: "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n/swapfile file 16777212 0 -2\n", ok: false},
	} {
		cfg, f := fakeUnitConfig(t, "1")
		f.layout = "v2-noswapacct"
		writeValue(t, filepath.Join(f.procRoot, "swaps"), tc.swaps)
		p, err := UnitLauncher(cfg)(context.Background())
		if tc.ok {
			if err != nil {
				t.Fatalf("no swap on host: launch = %v", err)
			}
			_ = p.Kill()
			<-p.Done()
			_ = p.Conn().Close()
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "cannot cap worker memory") {
			t.Fatalf("swap on host without accounting: launch = %v", err)
		}
	}
}

func TestUnitWatchdogKillsOverCap(t *testing.T) {
	cfg, f := fakeUnitConfig(t, "1")
	f.layout = "v1-memsw"
	p := launchUnit(t, cfg)
	writeValue(t, filepath.Join(f.cgroupDir(p.unit), "memory.memsw.usage_in_bytes"), strconv.Itoa(600<<20))
	deadline := time.Now().Add(time.Second)
	for len(f.kills()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("watchdog did not kill a worker over its cap")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUnitWatchdogRechecksSwapWithoutAccounting(t *testing.T) {
	for _, mode := range []string{"swap enabled", "swap status unreadable"} {
		t.Run(mode, func(t *testing.T) {
			cfg, f := fakeUnitConfig(t, "1")
			f.layout = "v2-noswapacct"
			swaps := filepath.Join(f.procRoot, "swaps")
			writeValue(t, swaps, "Filename\tType\tSize\tUsed\tPriority\n")
			p := launchUnit(t, cfg)
			if mode == "swap enabled" {
				writeValue(t, swaps, "Filename\tType\tSize\tUsed\tPriority\n/swapfile file 16777212 0 -2\n")
			} else if err := os.Rename(swaps, swaps+".unavailable"); err != nil {
				t.Fatal(err)
			}
			f.waitKills(t, 1)
			select {
			case <-p.Done():
			case <-time.After(reapTimeout):
				t.Fatal("worker survived without verifiable swap isolation")
			}
		})
	}
}

func TestUnitRetireAboveThreeQuarters(t *testing.T) {
	cfg, f := fakeUnitConfig(t, "1")
	f.layout = "v1-memsw"
	cfg.hooks.pollInterval = time.Hour
	p := launchUnit(t, cfg)
	usage := filepath.Join(f.cgroupDir(p.unit), "memory.memsw.usage_in_bytes")
	writeValue(t, usage, strconv.Itoa(400<<20))
	if !p.Retire() {
		t.Fatal("worker at 400 MiB of 512 MiB not retired")
	}
	writeValue(t, usage, strconv.Itoa(300<<20))
	if p.Retire() {
		t.Fatal("worker at 300 MiB of 512 MiB retired")
	}
	writeValue(t, usage, "unreadable")
	if !p.Retire() {
		t.Fatal("worker with unreadable usage not retired")
	}
}

func TestCgroupMemoryReadsRAMAndSwap(t *testing.T) {
	cg := memoryCgroup{dir: t.TempDir(), v2: true}
	writeValue(t, filepath.Join(cg.dir, "memory.current"), "1024000")
	writeValue(t, filepath.Join(cg.dir, "memory.swap.current"), "24576")
	got, err := cg.usage(t.TempDir())
	if err != nil || got != 1048576 {
		t.Fatalf("cgroup memory = %d, %v", got, err)
	}
}

// A unit is retired at three quarters of RuntimeMaxSec, so systemd's own cap
// never lands in the middle of a request.
func TestUnitRetireBeforeRuntimeMax(t *testing.T) {
	cfg, _ := fakeUnitConfig(t, "1")
	cfg.RuntimeMax = 200 * time.Millisecond
	cfg.hooks.pollInterval = time.Hour
	p := launchUnit(t, cfg)
	if p.Retire() {
		t.Fatal("fresh unit retired")
	}
	time.Sleep(160 * time.Millisecond)
	if !p.Retire() {
		t.Fatal("unit past three quarters of its lifetime cap not retired")
	}
}
