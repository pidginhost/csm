package workerproc

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// memoryCgroup is a worker unit's own memory cgroup directory.
type memoryCgroup struct {
	dir string
	v2  bool
}

// findMemoryCgroup reads the cgroup of pid from procRoot. A cgroup v1 memory
// controller line wins; otherwise the unified (v2) line is used. found is
// false when neither names a directory under cgroupRoot.
func findMemoryCgroup(procRoot, cgroupRoot string, pid int) (memoryCgroup, bool, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup")) // #nosec G304 -- procfs path built from a PID systemd reported.
	if err != nil {
		return memoryCgroup{}, false, err
	}
	var unified string
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			unified = parts[2]
			continue
		}
		for _, controller := range strings.Split(parts[1], ",") {
			if controller != "memory" {
				continue
			}
			if dir := filepath.Join(cgroupRoot, "memory", parts[2]); isDir(dir) {
				return memoryCgroup{dir: dir}, true, nil
			}
		}
	}
	if unified != "" {
		if dir := filepath.Join(cgroupRoot, unified); isDir(dir) {
			return memoryCgroup{dir: dir, v2: true}, true, nil
		}
	}
	return memoryCgroup{}, false, nil
}

func isDir(path string) bool {
	st, err := os.Stat(path) // #nosec G703 -- a cgroup path the kernel reported for a PID systemd reported.
	return err == nil && st.IsDir()
}

// capSwap makes the cgroup's memory cap cover swap too. On cgroup v1
// MemoryLimit caps RAM only: a worker over it swaps instead of dying, and a
// host with plenty of swap never stops it. Each write is read back, because a
// cap that silently did not take effect is no cap.
func (c memoryCgroup) capSwap(limit uint64) error {
	if c.v2 {
		swapMax := filepath.Join(c.dir, "memory.swap.max")
		current, err := readCgroupValue(swapMax)
		if errors.Is(err, os.ErrNotExist) {
			return nil // No swap controller: nothing to swap to.
		}
		if err != nil || current == "0" {
			return err
		}
		return writeCgroupValue(swapMax, "0", func(got string) bool { return got == "0" })
	}
	memsw := filepath.Join(c.dir, "memory.memsw.limit_in_bytes")
	if _, err := os.Stat(memsw); err == nil {
		return writeCgroupValue(memsw, strconv.FormatUint(limit, 10), func(got string) bool {
			// The kernel may round down to a page; anything above the cap,
			// such as the unlimited default, means the write did not land.
			n, parseErr := strconv.ParseUint(got, 10, 64)
			return parseErr == nil && n > 0 && n <= limit
		})
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// No swap accounting: keep the cgroup out of swap instead.
	return writeCgroupValue(filepath.Join(c.dir, "memory.swappiness"), "0", func(got string) bool { return got == "0" })
}

// usage is the cgroup's memory and swap in use. It counts memfd pages
// charged to the unit, which VmRSS misses.
func (c memoryCgroup) usage() (uint64, error) {
	if c.v2 {
		used, err := readCgroupUint(filepath.Join(c.dir, "memory.current"))
		if err != nil {
			return 0, err
		}
		swap, err := readCgroupUint(filepath.Join(c.dir, "memory.swap.current"))
		if errors.Is(err, os.ErrNotExist) {
			return used, nil
		}
		return used + swap, err
	}
	used, err := readCgroupUint(filepath.Join(c.dir, "memory.memsw.usage_in_bytes"))
	if errors.Is(err, os.ErrNotExist) {
		return readCgroupUint(filepath.Join(c.dir, "memory.usage_in_bytes"))
	}
	return used, err
}

// processMemory is VmRSS plus VmSwap of pid, for a worker whose cgroup
// cannot be found.
func processMemory(procRoot string, pid int) (uint64, error) {
	f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "status")) // #nosec G304 -- procfs path built from a PID systemd reported.
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var rss, swap uint64
	haveRSS := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), ":")
		if !ok || (key != "VmRSS" && key != "VmSwap") {
			continue
		}
		kb, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(value), " kB"), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("workerproc: %s of %d: %w", key, pid, err)
		}
		if key == "VmRSS" {
			rss, haveRSS = kb<<10, true
		} else {
			swap = kb << 10
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	if !haveRSS {
		return 0, fmt.Errorf("workerproc: no VmRSS for %d", pid)
	}
	return rss + swap, nil
}

func readCgroupValue(path string) (string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- a file in the worker unit's own cgroup.
	return strings.TrimSpace(string(b)), err
}

func readCgroupUint(path string) (uint64, error) {
	v, err := readCgroupValue(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(v, 10, 64)
}

// writeCgroupValue writes value without creating the file, then checks the
// value read back.
func writeCgroupValue(path, value string, ok func(string) bool) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0) // #nosec G304 -- a file in the worker unit's own cgroup.
	if err != nil {
		return err
	}
	_, err = f.WriteString(value)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	got, err := readCgroupValue(path)
	if err != nil {
		return err
	}
	if !ok(got) {
		return fmt.Errorf("%s reads %q after writing %s", path, got, value)
	}
	return nil
}
