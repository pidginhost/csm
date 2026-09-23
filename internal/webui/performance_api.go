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

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/mysqlclient"
	"github.com/pidginhost/csm/internal/redisinfo"
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
	// MySQL telemetry is best-effort. Both fields are nil when csm could
	// not read the server's process status or the mysql client failed (no /root/.my.cnf,
	// no socket auth, mysqld absent). The webui renders "n/a" in that case
	// so operators can tell "MySQL is idle" from "we couldn't ask".
	MySQLMemMB    *uint64 `json:"mysql_mem_mb"`
	MySQLConns    *int    `json:"mysql_conns"`
	RedisMemMB    uint64  `json:"redis_mem_mb"`
	RedisMaxMB    uint64  `json:"redis_maxmem_mb"`
	RedisKeys     int64   `json:"redis_keys"`
	UptimeSeconds int64   `json:"uptime_seconds"`
}

type userProcs struct {
	User  string `json:"user"`
	Count int    `json:"count"`
}

type perfFindingView struct {
	Severity  int       `json:"severity"`
	SevClass  string    `json:"sev_class"`
	Check     string    `json:"check"`
	Message   string    `json:"message"`
	Details   string    `json:"details,omitempty"`
	Key       string    `json:"key"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
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

// isPHPWorkerCmdline reports whether a /proc cmdline belongs to a PHP process
// that serves requests.
//
// Two forms exist across the supported stacks: LiteSpeed spawns lsphp, and
// cPanel EA4 on Apache runs php-fpm, whose workers retitle themselves
// "php-fpm: pool <name>" and run as the account user. Matching only lsphp
// reported zero PHP activity on every Apache host.
//
// The php-fpm master is excluded on purpose: it runs as root and serves no
// requests, so counting it would attribute per-account load to root.
func isPHPWorkerCmdline(cmdline string) bool {
	if strings.HasPrefix(cmdline, "php-fpm: pool ") {
		return true
	}
	if strings.HasPrefix(cmdline, "php-fpm: master") {
		return false
	}
	return strings.Contains(cmdline, "lsphp")
}

// isMySQLServerCmdline reports whether a /proc cmdline is the database server
// itself, as opposed to a client, a wrapper script, or a backup tool.
//
// The pid file used to be read from a hardcoded path, which does not exist on
// the cPanel/MariaDB hosts CSM primarily targets: MariaDB writes
// /var/lib/mysql/<host>.pid instead. Matching the process avoids maintaining a
// list of per-distribution pid paths.
func isMySQLServerCmdline(cmdline string) bool {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return false
	}
	base := filepath.Base(fields[0])
	// A shell running mysqld_safe has the shell as argv[0]; neither it nor the
	// wrapper is the server process.
	return base == "mysqld" || base == "mariadbd"
}

// mysqlServerRSSMB returns the resident set size of the running database
// server in MB, or nil when no server process is found.
func mysqlServerRSSMB() *uint64 {
	cmdlinePaths, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, cmdPath := range cmdlinePaths {
		// #nosec G304 -- cmdPath from /proc/*/cmdline glob; kernel pseudo-FS.
		data, err := os.ReadFile(cmdPath)
		if err != nil {
			continue
		}
		if !isMySQLServerCmdline(strings.ReplaceAll(string(data), "\x00", " ")) {
			continue
		}
		// #nosec G304 -- /proc/<pid>/status; kernel pseudo-FS.
		statusData, _ := os.ReadFile(filepath.Join(filepath.Dir(cmdPath), "status"))
		for _, line := range strings.Split(string(statusData), "\n") {
			if !strings.HasPrefix(line, "VmRSS:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, perr := strconv.ParseUint(fields[1], 10, 64); perr == nil {
					mb := kb / 1024
					return &mb
				}
			}
			break
		}
	}
	return nil
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

	// PHP processes: scan /proc/*/cmdline for PHP request workers.
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
			if !isPHPWorkerCmdline(cmdStr) {
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

	// MySQL: PID -> VmRSS, plus Threads_connected. Both fields stay nil
	// when the lookup fails so the webui can show "n/a" instead of a
	// misleading 0.
	{
		m.MySQLMemMB = mysqlServerRSSMB()
		// Connection count. mysqlclient open returns nil on auth failure,
		// missing socket, or absent server -- in every such case we
		// leave MySQLConns nil rather than reporting a fake 0.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		rows, err := mysqlclient.RootQuery(ctx, "SHOW STATUS LIKE 'Threads_connected'")
		cancel()
		if err == nil && len(rows) > 0 {
			fields := strings.Fields(rows[0])
			if len(fields) >= 2 {
				if n, perr := strconv.Atoi(fields[1]); perr == nil {
					m.MySQLConns = &n
				}
			}
		}
	}

	// Redis: memory + keyspace via in-process client (no redis-cli fork).
	{
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if used, max, err := redisinfo.MemoryUsage(ctx); err == nil {
			m.RedisMemMB = used / (1024 * 1024)
			m.RedisMaxMB = max / (1024 * 1024)
		}
		if total, err := redisinfo.Keyspace(ctx); err == nil {
			m.RedisKeys = total
		}
	}

	// Uptime from /proc/uptime
	{
		data, err := os.ReadFile("/proc/uptime")
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) >= 1 {
				secs, _ := strconv.ParseFloat(fields[0], 64)
				m.UptimeSeconds = int64(secs)
			}
		}
	}

	return m
}

// perfSampleTTL is how long a metrics sample is served before the next
// request takes a new one. Var so tests can force a fresh sample.
var perfSampleTTL = 10 * time.Second

// perfSample is one metrics sample and when it was taken.
type perfSample struct {
	metrics *perfMetrics
	at      time.Time
}

func (s *Server) storePerfSample(m *perfMetrics, at time.Time) {
	s.perfSample.Store(&perfSample{metrics: m, at: at})
}

func (s *Server) freshPerfSample() (*perfMetrics, bool) {
	p := s.perfSample.Load()
	if p == nil || time.Since(p.at) >= perfSampleTTL {
		return nil, false
	}
	return p.metrics, true
}

// currentPerfMetrics returns a sample no older than perfSampleTTL, taking
// one if needed. Requests that arrive while a sample is being taken wait for
// it instead of sampling again.
func (s *Server) currentPerfMetrics() *perfMetrics {
	if m, ok := s.freshPerfSample(); ok {
		return m
	}
	s.perfMu.Lock()
	defer s.perfMu.Unlock()
	if m, ok := s.freshPerfSample(); ok {
		return m
	}
	sample := s.samplePerf
	if sample == nil {
		sample = sampleMetrics
	}
	m := sample()
	s.storePerfSample(m, time.Now())
	return m
}

// apiPerformance returns the latest performance snapshot plus perf_ findings.
func (s *Server) apiPerformance(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	if limit > 500 {
		limit = 500
	}

	metrics := s.currentPerfMetrics()

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
		key := f.Key()
		views = append(views, perfFindingView{
			Severity:  int(f.Severity),
			SevClass:  severityClass(f.Severity),
			Check:     f.Check,
			Message:   f.Message,
			Details:   f.Details,
			Key:       key,
			FirstSeen: firstSeen.UTC(),
			LastSeen:  lastSeen.UTC(),
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

// apiPerfFixErrorLog truncates an account-owned error_log identified by
// the perf_error_logs finding. Admin scope; CSRF enforced at the route.
func (s *Server) apiPerfFixErrorLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path string `json:"path"`
		Key  string `json:"key"`
	}
	if err := decodeJSONBodyLimited(w, r, 1<<14, &req); err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		writeJSONError(w, "path is required", http.StatusBadRequest)
		return
	}
	res := checks.FixErrorLogBloatInRoots(req.Path, s.perfFixAllowedRoots())
	if !res.Success {
		writeRemediation(w, res)
		return
	}
	s.dismissPerfFinding(req.Key)
	s.auditLog(r, "perf_fix_error_log", req.Path, res.Description)
	writeRemediation(w, res)
}

// apiPerfFixDisplayErrors disables display_errors in an account-owned
// .user.ini / php.ini / .htaccess identified by the perf_wp_config
// finding's Details field. Admin scope; CSRF enforced at the route.
//
//nolint:dupl // mirrors apiPerfFixErrorLog; separate handlers keep audit actions explicit.
func (s *Server) apiPerfFixDisplayErrors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path string `json:"path"`
		Key  string `json:"key"`
	}
	if err := decodeJSONBodyLimited(w, r, 1<<14, &req); err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		writeJSONError(w, "path is required", http.StatusBadRequest)
		return
	}
	res := checks.FixDisplayErrorsOnInRoots(req.Path, s.perfFixAllowedRoots())
	if !res.Success {
		writeRemediation(w, res)
		return
	}
	s.dismissPerfFinding(req.Key)
	s.auditLog(r, "perf_fix_display_errors", req.Path, res.Description)
	writeRemediation(w, res)
}

// apiPerfFixWPCron disables WP-Cron in an account-owned wp-config.php
// identified by a perf_wp_cron finding and installs a per-user system cron
// that runs wp-cron.php. Admin scope; CSRF enforced at the route.
func (s *Server) apiPerfFixWPCron(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path string `json:"path"`
		Key  string `json:"key"`
	}
	if err := decodeJSONBodyLimited(w, r, 1<<14, &req); err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		writeJSONError(w, "path is required", http.StatusBadRequest)
		return
	}
	cfg := s.liveCfg()
	options := checks.WPCronFixOptions{}
	if cfg != nil {
		options.IntervalMinutes = cfg.Performance.WPCronFix.IntervalMinutes
		options.PHPBin = cfg.Performance.WPCronFix.PHPBin
	}
	res := checks.FixDisableWPCronInRoots(req.Path, checks.ResolveWPCronRoots(cfg), options)
	if !res.Success {
		writeRemediation(w, res)
		return
	}
	s.dismissPerfFinding(req.Key)
	s.auditLog(r, "perf_fix_wp_cron", req.Path, res.Description)
	writeRemediation(w, res)
}

func (s *Server) perfFixAllowedRoots() []string {
	cfg := s.liveCfg()
	if cfg == nil {
		return []string{"/home"}
	}
	return checks.ResolveWebRoots(cfg)
}

func (s *Server) dismissPerfFinding(key string) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	s.store.DismissFinding(key)
	s.store.DismissLatestFinding(key)
}

// handlePerformance renders the performance dashboard page.
func (s *Server) handlePerformance(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, "performance.html", nil)
}
