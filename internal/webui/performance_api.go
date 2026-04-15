package webui

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Local response types ---

type perfResponse struct {
	Metrics  *perfMetrics      `json:"metrics"`
	Findings []perfFindingView `json:"findings"`
}

type perfMetrics struct {
	LoadAvg     [3]float64  `json:"load_avg"`
	CPUCores    int         `json:"cpu_cores"`
	MemTotalMB  uint64      `json:"mem_total_mb"`
	MemUsedMB   uint64      `json:"mem_used_mb"`
	MemAvailMB  uint64      `json:"mem_avail_mb"`
	SwapTotalMB uint64      `json:"swap_total_mb"`
	SwapUsedMB  uint64      `json:"swap_used_mb"`
	PHPProcs    int         `json:"php_procs_total"`
	TopPHPUsers []userProcs `json:"top_php_users"`
	MySQLMemMB  uint64      `json:"mysql_mem_mb"`
	MySQLConns  int         `json:"mysql_conns"`
	RedisMemMB  uint64      `json:"redis_mem_mb"`
	RedisMaxMB  uint64      `json:"redis_maxmem_mb"`
	RedisKeys   int64       `json:"redis_keys"`
	Uptime      string      `json:"uptime"`
}

type userProcs struct {
	User  string `json:"user"`
	Count int    `json:"count"`
}

type perfFindingView struct {
	Severity  int    `json:"severity"`
	SevClass  string `json:"sev_class"`
	Check     string `json:"check"`
	Message   string `json:"message"`
	Details   string `json:"details,omitempty"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// --- Cached values ---

var (
	perfCoresOnce  sync.Once
	perfCoresCache int

	perfUIDMapOnce  sync.Once
	perfUIDMapCache map[string]string
)

// cachedCores reads /proc/cpuinfo once and counts "processor\t" lines.
func cachedCores() int {
	perfCoresOnce.Do(func() {
		f, err := os.Open("/proc/cpuinfo")
		if err != nil {
			perfCoresCache = 1
			return
		}
		defer func() { _ = f.Close() }()

		count := 0
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "processor\t") {
				count++
			}
		}
		if count == 0 {
			count = 1
		}
		perfCoresCache = count
	})
	return perfCoresCache
}

// cachedUID resolves a UID string to a username via /etc/passwd, cached.
func cachedUID(uid string) string {
	perfUIDMapOnce.Do(func() {
		perfUIDMapCache = make(map[string]string)
		data, err := os.ReadFile("/etc/passwd")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) >= 3 {
				perfUIDMapCache[fields[2]] = fields[0]
			}
		}
	})
	if name, ok := perfUIDMapCache[uid]; ok {
		return name
	}
	return uid
}

// --- Metrics sampler ---

// runCmdQuick runs a command with a 5-second timeout. All call sites pass
// constant binary names (mysql, redis-cli, etc.) and literal argument
// lists — no HTTP-controlled input reaches this function.
func runCmdQuick(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// #nosec G204 -- see function-level comment: constant names/args only.
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("command timed out: %s", name)
	}
	return out, err
}

// sampleMetrics gathers live system metrics and returns a populated perfMetrics.
func sampleMetrics() *perfMetrics {
	m := &perfMetrics{}

	// Load averages
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			for i := 0; i < 3; i++ {
				v, _ := strconv.ParseFloat(fields[i], 64)
				m.LoadAvg[i] = v
			}
		}
	}

	// CPU cores
	m.CPUCores = cachedCores()

	// Memory from /proc/meminfo
	{
		f, err := os.Open("/proc/meminfo")
		if err == nil {
			var memTotal, memAvail, memFree, memBuffers, memCached, swapTotal, swapFree uint64
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := scanner.Text()
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				val, _ := strconv.ParseUint(fields[1], 10, 64)
				switch fields[0] {
				case "MemTotal:":
					memTotal = val
				case "MemAvailable:":
					memAvail = val
				case "MemFree:":
					memFree = val
				case "Buffers:":
					memBuffers = val
				case "Cached:":
					memCached = val
				case "SwapTotal:":
					swapTotal = val
				case "SwapFree:":
					swapFree = val
				}
			}
			_ = f.Close()

			m.MemTotalMB = memTotal / 1024
			m.MemAvailMB = memAvail / 1024
			// Used = Total - Free - Buffers - Cached
			used := memTotal
			if memFree+memBuffers+memCached <= memTotal {
				used = memTotal - memFree - memBuffers - memCached
			}
			m.MemUsedMB = used / 1024
			m.SwapTotalMB = swapTotal / 1024
			if swapFree <= swapTotal {
				m.SwapUsedMB = (swapTotal - swapFree) / 1024
			}
		}
	}

	// PHP processes: scan /proc/*/cmdline for lsphp
	{
		cmdlinePaths, _ := filepath.Glob("/proc/[0-9]*/cmdline")
		userCounts := make(map[string]int)
		total := 0
		for _, cmdPath := range cmdlinePaths {
			// #nosec G304 -- cmdPath from /proc/*/cmdline glob; kernel pseudo-FS.
			data, err := os.ReadFile(cmdPath)
			if err != nil {
				continue
			}
			cmdStr := strings.ReplaceAll(string(data), "\x00", " ")
			if !strings.Contains(cmdStr, "lsphp") {
				continue
			}
			pid := filepath.Base(filepath.Dir(cmdPath))
			// #nosec G304 -- /proc/<pid>/status; kernel pseudo-FS, pid from /proc glob.
			statusData, _ := os.ReadFile(filepath.Join("/proc", pid, "status"))
			uid := ""
			for _, line := range strings.Split(string(statusData), "\n") {
				if strings.HasPrefix(line, "Uid:\t") {
					f := strings.Fields(strings.TrimPrefix(line, "Uid:\t"))
					if len(f) > 0 {
						uid = f[0]
					}
					break
				}
			}
			if uid == "" {
				uid = "unknown"
			}
			username := cachedUID(uid)
			userCounts[username]++
			total++
		}
		m.PHPProcs = total

		// Build sorted top-10 list
		type up struct {
			user  string
			count int
		}
		var ups []up
		for u, c := range userCounts {
			ups = append(ups, up{u, c})
		}
		sort.Slice(ups, func(i, j int) bool {
			return ups[i].count > ups[j].count
		})
		if len(ups) > 10 {
			ups = ups[:10]
		}
		m.TopPHPUsers = make([]userProcs, len(ups))
		for i, u := range ups {
			m.TopPHPUsers[i] = userProcs{User: u.user, Count: u.count}
		}
	}

	// MySQL: PID → VmRSS, plus Threads_connected
	{
		pidData, err := os.ReadFile("/var/run/mysqld/mysqld.pid")
		if err == nil {
			mysqlPID := strings.TrimSpace(string(pidData))
			if mysqlPID != "" {
				// #nosec G304 G703 -- mysqlPID is read from mysqld's own
				// /var/run/mysqld/mysqld.pid and we're reading the kernel
				// /proc pseudo-filesystem.
				statusData, _ := os.ReadFile(filepath.Join("/proc", mysqlPID, "status"))
				for _, line := range strings.Split(string(statusData), "\n") {
					if strings.HasPrefix(line, "VmRSS:") {
						fields := strings.Fields(line)
						if len(fields) >= 2 {
							kb, _ := strconv.ParseUint(fields[1], 10, 64)
							m.MySQLMemMB = kb / 1024
						}
						break
					}
				}
			}
		}
		// Connection count
		out, err := runCmdQuick("mysql", "-N", "-B", "-e", "SHOW STATUS LIKE 'Threads_connected'")
		if err == nil && len(out) > 0 {
			fields := strings.Fields(string(out))
			if len(fields) >= 2 {
				n, _ := strconv.Atoi(fields[1])
				m.MySQLConns = n
			}
		}
	}

	// Redis: memory + keyspace
	{
		memOut, err := runCmdQuick("redis-cli", "info", "memory")
		if err == nil && len(memOut) > 0 {
			for _, line := range strings.Split(string(memOut), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "used_memory:") {
					val := strings.TrimPrefix(line, "used_memory:")
					bytes, _ := strconv.ParseUint(strings.TrimSpace(val), 10, 64)
					m.RedisMemMB = bytes / (1024 * 1024)
				} else if strings.HasPrefix(line, "maxmemory:") {
					val := strings.TrimPrefix(line, "maxmemory:")
					bytes, _ := strconv.ParseUint(strings.TrimSpace(val), 10, 64)
					m.RedisMaxMB = bytes / (1024 * 1024)
				}
			}
		}
		ksOut, err := runCmdQuick("redis-cli", "info", "keyspace")
		if err == nil && len(ksOut) > 0 {
			var totalKeys int64
			for _, line := range strings.Split(string(ksOut), "\n") {
				line = strings.TrimSpace(line)
				// Lines like: db0:keys=1234,expires=5,avg_ttl=0
				if !strings.HasPrefix(line, "db") {
					continue
				}
				parts := strings.SplitN(line, ":", 2)
				if len(parts) < 2 {
					continue
				}
				for _, kv := range strings.Split(parts[1], ",") {
					if strings.HasPrefix(kv, "keys=") {
						n, _ := strconv.ParseInt(strings.TrimPrefix(kv, "keys="), 10, 64)
						totalKeys += n
					}
				}
			}
			m.RedisKeys = totalKeys
		}
	}

	// Uptime from /proc/uptime
	{
		data, err := os.ReadFile("/proc/uptime")
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) >= 1 {
				secs, _ := strconv.ParseFloat(fields[0], 64)
				d := time.Duration(secs) * time.Second
				days := int(d.Hours()) / 24
				hours := int(d.Hours()) % 24
				m.Uptime = fmt.Sprintf("%dd %dh", days, hours)
			}
		}
	}

	return m
}

// sampleMetricsLoop samples metrics immediately and then every 10 seconds.
func (s *Server) sampleMetricsLoop(ctx context.Context) {
	result := sampleMetrics()
	s.perfSnapshot.Store(result)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result := sampleMetrics()
			s.perfSnapshot.Store(result)
		}
	}
}

// apiPerformance returns the latest performance snapshot plus perf_ findings.
func (s *Server) apiPerformance(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	if limit > 500 {
		limit = 500
	}

	metrics := s.perfSnapshot.Load()

	latest := s.store.LatestFindings()
	suppressions := s.store.LoadSuppressions()

	var views []perfFindingView
	for _, f := range latest {
		if !strings.HasPrefix(f.Check, "perf_") {
			continue
		}
		if s.store.IsSuppressed(f, suppressions) {
			continue
		}
		firstSeen := f.Timestamp
		lastSeen := f.Timestamp
		if entry, ok := s.store.EntryForKey(f.Key()); ok {
			firstSeen = entry.FirstSeen
			lastSeen = entry.LastSeen
		}
		views = append(views, perfFindingView{
			Severity:  int(f.Severity),
			SevClass:  severityClass(f.Severity),
			Check:     f.Check,
			Message:   f.Message,
			Details:   f.Details,
			FirstSeen: firstSeen.Format(time.RFC3339),
			LastSeen:  lastSeen.Format(time.RFC3339),
		})
	}

	// Sort by severity descending
	sort.Slice(views, func(i, j int) bool {
		return views[i].Severity > views[j].Severity
	})

	if len(views) > limit {
		views = views[:limit]
	}

	writeJSON(w, perfResponse{
		Metrics:  metrics,
		Findings: views,
	})
}

// handlePerformance renders the performance dashboard page.
func (s *Server) handlePerformance(w http.ResponseWriter, _ *http.Request) {
	s.renderTemplate(w, "performance.html", nil)
}
