package workerproc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// memorySampler records a worker cgroup's memory counters and the worker's
// resident set while a test waits on it. A run that thrashes at its cap
// instead of reaching an OOM kill then shows what the cgroup keeps freeing.
type memorySampler struct {
	stop  chan struct{}
	done  chan struct{}
	once  sync.Once
	lines []string
}

var (
	sampledMemoryStat   = []string{"anon", "file", "file_mapped", "shmem", "anon_thp", "workingset_refault_anon", "workingset_refault_file", "pgscan", "pgsteal", "pgmajfault", "thp_fault_alloc"}
	sampledMemoryEvents = []string{"max", "oom", "oom_kill"}
	sampledProcStatus   = []string{"RssAnon", "RssFile", "RssShmem"}
)

// startMemorySampler samples cgDir and procDir (a /proc/<pid> directory) at
// once and then on every tick, until Stop or until the cgroup is gone.
func startMemorySampler(cgDir, procDir string, tick <-chan time.Time) *memorySampler {
	s := &memorySampler{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		start := time.Now()
		for {
			line, ok := memorySample(cgDir, procDir)
			if !ok {
				return
			}
			s.lines = append(s.lines, fmt.Sprintf("%.1fs %s", time.Since(start).Seconds(), line))
			select {
			case <-s.stop:
				return
			case <-tick:
			}
		}
	}()
	return s
}

// Stop ends sampling and returns the samples. It may be called more than once.
func (s *memorySampler) Stop() []string {
	s.once.Do(func() { close(s.stop) })
	<-s.done
	return s.lines
}

func memorySample(cgDir, procDir string) (string, bool) {
	current, err := os.ReadFile(filepath.Join(cgDir, "memory.current")) // #nosec G304 -- test helper reading a cgroup it launched.
	if err != nil {
		return "", false
	}
	var b strings.Builder
	fmt.Fprintf(&b, "current=%s", kib(strings.TrimSpace(string(current))))
	stat := keyedFields(filepath.Join(cgDir, "memory.stat"), " ")
	for _, k := range sampledMemoryStat {
		if v, ok := stat[k]; ok {
			if k == "anon" || k == "file" || k == "file_mapped" || k == "shmem" || k == "anon_thp" {
				v = kib(v)
			}
			fmt.Fprintf(&b, " %s=%s", k, v)
		}
	}
	events := keyedFields(filepath.Join(cgDir, "memory.events"), " ")
	for _, k := range sampledMemoryEvents {
		fmt.Fprintf(&b, " %s=%s", k, events[k])
	}
	status := keyedFields(filepath.Join(procDir, "status"), ":")
	for _, k := range sampledProcStatus {
		if v, ok := status[k]; ok {
			fmt.Fprintf(&b, " %s=%s", k, strings.ReplaceAll(v, " ", ""))
		}
	}
	return b.String(), true
}

// keyedFields reads "key<sep>value" lines; a missing file yields no fields.
func keyedFields(path, sep string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path) // #nosec G304 -- test helper reading cgroup and proc files.
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), sep); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// kib shows a byte count in KiB, the unit /proc/<pid>/status uses.
func kib(bytes string) string {
	n, err := strconv.ParseUint(bytes, 10, 64)
	if err != nil {
		return bytes
	}
	return strconv.FormatUint(n>>10, 10) + "K"
}

func writeMemoryFixture(t *testing.T, cg, proc string) {
	t.Helper()
	files := map[string]string{
		filepath.Join(cg, "memory.current"): "67108864\n",
		filepath.Join(cg, "memory.stat"):    "anon 62914560\nfile 4194304\nanon_thp 2097152\nworkingset_refault_file 7\npgsteal 11\nslab 1024\n",
		filepath.Join(cg, "memory.events"):  "low 0\nhigh 0\nmax 42\noom 0\noom_kill 0\noom_group_kill 0\n",
		filepath.Join(proc, "status"):       "Name:\tworker\nVmRSS:\t   65536 kB\nRssAnon:\t   61440 kB\nRssFile:\t    4096 kB\nRssShmem:\t       0 kB\n",
	}
	for name, body := range files {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMemorySamplerRecordsCountersUntilStopped(t *testing.T) {
	cg, proc := t.TempDir(), t.TempDir()
	writeMemoryFixture(t, cg, proc)
	tick := make(chan time.Time)
	s := startMemorySampler(cg, proc, tick)
	// Each send returns once the sampler waits for it, so it samples once per send.
	tick <- time.Now()
	tick <- time.Now()
	lines := s.Stop()
	if len(lines) != 3 {
		t.Fatalf("got %d samples, want one at start and one per tick: %q", len(lines), lines)
	}
	for _, want := range []string{"current=65536K", "anon=61440K", "file=4096K", "anon_thp=2048K", "workingset_refault_file=7", "pgsteal=11", "max=42", "oom_kill=0", "RssAnon=61440kB", "RssFile=4096kB"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("sample %q lacks %s", lines[0], want)
		}
	}
	if strings.Contains(lines[0], "slab") {
		t.Errorf("sample %q holds a counter that was not asked for", lines[0])
	}
	if again := s.Stop(); len(again) != len(lines) {
		t.Errorf("second Stop returned %d samples, want the same %d", len(again), len(lines))
	}
}

// The unit's cgroup disappears when systemd collects it after an OOM kill;
// sampling ends on its own and Stop must not block.
func TestMemorySamplerEndsWhenCgroupGoes(t *testing.T) {
	cg, proc := t.TempDir(), t.TempDir()
	writeMemoryFixture(t, cg, proc)
	if err := os.Remove(filepath.Join(cg, "memory.current")); err != nil {
		t.Fatal(err)
	}
	s := startMemorySampler(cg, proc, make(chan time.Time))
	done := make(chan []string)
	go func() { done <- s.Stop() }()
	select {
	case lines := <-done:
		if len(lines) != 0 {
			t.Errorf("samples from a missing cgroup: %q", lines)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop blocked after the cgroup went away")
	}
}
