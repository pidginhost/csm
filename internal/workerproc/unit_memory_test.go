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
		return filepath.Join(f.cgroupRoot, "memory", "system.slice", unit+".service")
	}
	return filepath.Join(f.cgroupRoot, "system.slice", unit+".service")
}

// writeCgroup builds the fake /proc/<pid>/cgroup and cgroup files the way a
// unit started by systemd would see them.
func (f *unitFake) writeCgroup(pid int, unit string) error {
	if f.layout == "none" {
		return nil
	}
	path := "/system.slice/" + unit + ".service"
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
	dir := f.cgroupDir(unit)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	files := map[string]string{}
	switch f.layout {
	case "v2":
		files = map[string]string{"memory.current": "1048576", "memory.swap.current": "0", "memory.swap.max": "max"}
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
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
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
	cg, found, err := findMemoryCgroup(proc, root, 42)
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

func TestProcessMemoryReadsRSSAndSwap(t *testing.T) {
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "7"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeValue(t, filepath.Join(proc, "7", "status"), "Name:\tcsm\nVmRSS:\t    1000 kB\nVmSwap:\t      24 kB\n")
	got, err := processMemory(proc, 7)
	if err != nil || got != 1048576 {
		t.Fatalf("processMemory = %d, %v", got, err)
	}
}
