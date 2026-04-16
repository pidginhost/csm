package checks

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// perfEnabled returns false only if Performance.Enabled is explicitly set to false.
// nil (unset) is treated as enabled.
func perfEnabled(cfg *config.Config) bool {
	if cfg.Performance.Enabled == nil {
		return true
	}
	return *cfg.Performance.Enabled
}

// cpuCoresOnce guards the cached CPU core count.
var (
	cpuCoresOnce  sync.Once
	cpuCoresCache int
)

// getCPUCores reads /proc/cpuinfo and counts "processor\t" lines.
// The result is cached after the first call. Returns 1 on error.
func getCPUCores() int {
	cpuCoresOnce.Do(func() {
		f, err := osFS.Open("/proc/cpuinfo")
		if err != nil {
			cpuCoresCache = 1
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
		cpuCoresCache = count
	})
	return cpuCoresCache
}

// parseLoadAvg reads /proc/loadavg and returns the first three load average
// values (1m, 5m, 15m).
func parseLoadAvg() ([3]float64, error) {
	var result [3]float64

	data, err := osFS.ReadFile("/proc/loadavg")
	if err != nil {
		return result, fmt.Errorf("reading /proc/loadavg: %w", err)
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return result, fmt.Errorf("unexpected /proc/loadavg format: %q", string(data))
	}

	for i := 0; i < 3; i++ {
		v, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return result, fmt.Errorf("parsing load avg field %d: %w", i, err)
		}
		result[i] = v
	}

	return result, nil
}

// parseMemInfo reads /proc/meminfo and returns total memory, available memory,
// swap total, and swap free - all in kilobytes.
func parseMemInfo() (total, available, swapTotal, swapFree uint64) {
	f, err := osFS.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := fields[0]
		val, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "MemTotal:":
			total = val
		case "MemAvailable:":
			available = val
		case "SwapTotal:":
			swapTotal = val
		case "SwapFree:":
			swapFree = val
		}
	}
	return
}

// humanBytes formats a byte count as a human-readable string.
// Thresholds: >=1G → "1.0G", >=1M → "1M", >=1K → "1K", else "0B".
func humanBytes(b int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1fG", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%dM", b/MB)
	case b >= KB:
		return fmt.Sprintf("%dK", b/KB)
	default:
		return "0B"
	}
}

// CheckLoadAverage compares the 1-minute load average against per-core
// thresholds from config. Reports Critical or High findings.
func CheckLoadAverage(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}

	loads, err := parseLoadAvg()
	if err != nil {
		return nil
	}

	cores := getCPUCores()
	load1 := loads[0]

	critThreshold := float64(cores) * cfg.Performance.LoadCriticalMultiplier
	highThreshold := float64(cores) * cfg.Performance.LoadHighMultiplier

	var sev alert.Severity
	var msg string

	switch {
	case load1 > critThreshold:
		sev = alert.Critical
		msg = "High load average exceeds critical threshold"
	case load1 > highThreshold:
		sev = alert.High
		msg = "High load average exceeds high threshold"
	default:
		return nil
	}

	details := fmt.Sprintf("Load: %.1f/%.1f/%.1f, Cores: %d, Threshold: %.1f",
		loads[0], loads[1], loads[2], cores,
		map[bool]float64{true: critThreshold, false: highThreshold}[sev == alert.Critical])

	return []alert.Finding{{
		Severity:  sev,
		Check:     "perf_load",
		Message:   msg,
		Details:   details,
		Timestamp: time.Now(),
	}}
}

// CheckPHPProcessLoad scans /proc for lsphp processes, groups them by user,
// and fires Critical if total exceeds cores*multiplier, High per user if
// individual count exceeds threshold.
func CheckPHPProcessLoad(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}

	cores := getCPUCores()

	cmdlinePaths, _ := osFS.Glob("/proc/[0-9]*/cmdline")

	// user → list of cmdline samples
	userProcs := make(map[string][]string)
	total := 0

	for _, cmdPath := range cmdlinePaths {
		pid := filepath.Base(filepath.Dir(cmdPath))

		data, err := osFS.ReadFile(cmdPath)
		if err != nil {
			continue
		}
		cmdStr := strings.ReplaceAll(string(data), "\x00", " ")
		cmdStr = strings.TrimSpace(cmdStr)

		if !strings.Contains(cmdStr, "lsphp") {
			continue
		}

		// Read UID from status
		statusData, _ := osFS.ReadFile(filepath.Join("/proc", pid, "status"))
		var uid string
		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, "Uid:\t") {
				fields := strings.Fields(strings.TrimPrefix(line, "Uid:\t"))
				if len(fields) > 0 {
					uid = fields[0]
				}
				break
			}
		}
		if uid == "" {
			uid = "unknown"
		}

		username := uidToUser(uid)
		userProcs[username] = append(userProcs[username], cmdStr)
		total++
	}

	if total == 0 {
		return nil
	}

	var findings []alert.Finding

	// Critical: total lsphp count exceeds cores * multiplier
	critTotalThreshold := cores * cfg.Performance.PHPProcessCriticalTotalMult
	if total > critTotalThreshold {
		findings = append(findings, alert.Finding{
			Severity:  alert.Critical,
			Check:     "perf_php_processes",
			Message:   "Total lsphp process count exceeds critical threshold",
			Details:   fmt.Sprintf("Count: %d, Threshold: %d (cores: %d × %d)", total, critTotalThreshold, cores, cfg.Performance.PHPProcessCriticalTotalMult),
			Timestamp: time.Now(),
		})
	}

	// High: per-user count exceeds threshold
	for username, procs := range userProcs {
		if len(procs) > cfg.Performance.PHPProcessWarnPerUser {
			// Collect up to 3 sample cmdlines
			samples := procs
			if len(samples) > 3 {
				samples = samples[:3]
			}
			findings = append(findings, alert.Finding{
				Severity:  alert.High,
				Check:     "perf_php_processes",
				Message:   fmt.Sprintf("Excessive lsphp processes for user %s", username),
				Details:   fmt.Sprintf("Count: %d, Threshold: %d, Sample cmdlines: %s", len(procs), cfg.Performance.PHPProcessWarnPerUser, strings.Join(samples, " | ")),
				Timestamp: time.Now(),
			})
		}
	}

	return findings
}

// CheckSwapAndOOM checks for OOM killer events in dmesg and elevated swap
// usage from /proc/meminfo. Reports Critical for OOM, High for swap > 50%.
func CheckSwapAndOOM(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}

	var findings []alert.Finding

	// Check dmesg for OOM events
	// Prefer ISO timestamps so we can filter to the last hour.
	// Fall back to -T (human-readable) on older kernels that don't support --time-format.
	dmesgOut, isoErr := runCmd("dmesg", "--time-format", "iso", "--level=err")
	useISO := isoErr == nil && dmesgOut != nil
	if !useISO {
		dmesgOut, _ = runCmd("dmesg", "--level=err", "-T")
	}
	if dmesgOut != nil {
		cutoff := time.Now().Add(-1 * time.Hour)
		for _, line := range strings.Split(string(dmesgOut), "\n") {
			lower := strings.ToLower(line)
			if !strings.Contains(lower, "out of memory") && !strings.Contains(lower, "oom_reaper") {
				continue
			}
			if useISO {
				// ISO format: 2006-01-02T15:04:05,000000+0300
				// The timestamp is the first field before the first space.
				ts := strings.SplitN(line, " ", 2)[0]
				// Normalise: replace comma-decimal with period so time.Parse handles it.
				ts = strings.Replace(ts, ",", ".", 1)
				// Try parsing with timezone offset (+hhmm or +hh:mm).
				var parsed time.Time
				var parseErr error
				for _, layout := range []string{"2006-01-02T15:04:05.000000-0700", "2006-01-02T15:04:05.000000-07:00"} {
					parsed, parseErr = time.Parse(layout, ts)
					if parseErr == nil {
						break
					}
				}
				if parseErr != nil || parsed.Before(cutoff) {
					continue
				}
			}
			message := "OOM killer detected in dmesg"
			if useISO {
				message = "OOM killer invoked in the last hour"
			}
			findings = append(findings, alert.Finding{
				Severity:  alert.Critical,
				Check:     "perf_memory",
				Message:   message,
				Details:   strings.TrimSpace(line),
				Timestamp: time.Now(),
			})
			break // one finding is enough
		}
	}

	// Check swap usage
	_, _, swapTotal, swapFree := parseMemInfo()
	if swapTotal > 0 {
		swapUsed := swapTotal - swapFree
		usagePct := float64(swapUsed) / float64(swapTotal) * 100

		if usagePct > 50 {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "perf_memory",
				Message:  "High swap usage",
				// #nosec G115 -- swap sizes from /proc/meminfo are kernel-bounded
				// to physical memory, multiple orders below int64 max even after *1024.
				Details:   fmt.Sprintf("Swap used: %s / %s (%.0f%%)", humanBytes(int64(swapUsed)*1024), humanBytes(int64(swapTotal)*1024), usagePct),
				Timestamp: time.Now(),
			})
		}
	}

	return findings
}

// CheckPHPHandler detects PHP CGI handler usage on LiteSpeed servers.
// On LiteSpeed, CGI is significantly slower than LSAPI; this check fires
// a Critical finding for each PHP version using the CGI handler.
func CheckPHPHandler(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}
	if !store.ShouldRunThrottled("perf_php_handler", 60) {
		return nil
	}

	// Only relevant on LiteSpeed
	if _, err := osFS.Stat("/usr/local/lsws/bin/litespeed"); err != nil {
		return nil
	}

	var cgiVersions []string

	// Try whmapi1 first
	out, err := runCmd("whmapi1", "php_get_handlers", "--output=json")
	if err == nil && len(out) > 0 {
		// Parse JSON: look for handler entries with type "cgi"
		var result struct {
			Data struct {
				Handlers []struct {
					Version string `json:"version"`
					Handler string `json:"handler"`
					Type    string `json:"type"`
				} `json:"handlers"`
			} `json:"data"`
		}
		if jsonErr := json.Unmarshal(out, &result); jsonErr == nil {
			for _, h := range result.Data.Handlers {
				t := strings.ToLower(h.Handler + " " + h.Type)
				if strings.Contains(t, "cgi") && !strings.Contains(t, "lsapi") && !strings.Contains(t, "fpm") {
					cgiVersions = append(cgiVersions, h.Version)
				}
			}
		}
	} else {
		// Fallback: read /etc/cpanel/ea4/ea4.conf
		data, readErr := osFS.ReadFile("/etc/cpanel/ea4/ea4.conf")
		if readErr == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				// Lines like: ea-php74.handler = cgi
				if !strings.Contains(line, ".handler") {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				if len(parts) != 2 {
					continue
				}
				val := strings.TrimSpace(parts[1])
				if val == "cgi" {
					versionPart := strings.TrimSpace(parts[0])
					cgiVersions = append(cgiVersions, versionPart)
				}
			}
		}
	}

	if len(cgiVersions) == 0 {
		return nil
	}

	return []alert.Finding{{
		Severity:  alert.Critical,
		Check:     "perf_php_handler",
		Message:   "PHP handler set to CGI instead of LSAPI on LiteSpeed",
		Details:   fmt.Sprintf("Affected PHP versions: %s", strings.Join(cgiVersions, ", ")),
		Timestamp: time.Now(),
	}}
}

// CheckMySQLConfig inspects MySQL global variables and runtime status for
// performance-impacting misconfigurations. Each issue emits its own finding
// with a stable message so deduplication works correctly.
func CheckMySQLConfig(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}
	if !store.ShouldRunThrottled("perf_mysql_config", 60) {
		return nil
	}

	var findings []alert.Finding

	// --- Global variables ---
	varOut, err := runCmd("mysql", "-N", "-B", "-e",
		"SHOW GLOBAL VARIABLES WHERE Variable_name IN ('join_buffer_size','wait_timeout','interactive_timeout','max_user_connections','slow_query_log')")
	if err == nil && len(varOut) > 0 {
		joinBufThresholdBytes := int64(cfg.Performance.MySQLJoinBufferMaxMB) * 1024 * 1024
		waitTimeoutMax := cfg.Performance.MySQLWaitTimeoutMax

		for _, line := range strings.Split(string(varOut), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			name := fields[0]
			val := fields[1]

			switch name {
			case "join_buffer_size":
				v, convErr := strconv.ParseInt(val, 10, 64)
				if convErr == nil && v > joinBufThresholdBytes {
					findings = append(findings, alert.Finding{
						Severity:  alert.Critical,
						Check:     "perf_mysql_config",
						Message:   "MySQL join_buffer_size exceeds safe maximum",
						Details:   fmt.Sprintf("Current: %s, Max: %s", humanBytes(v), humanBytes(joinBufThresholdBytes)),
						Timestamp: time.Now(),
					})
				}
			case "wait_timeout":
				v, convErr := strconv.Atoi(val)
				if convErr == nil && v > waitTimeoutMax {
					findings = append(findings, alert.Finding{
						Severity:  alert.High,
						Check:     "perf_mysql_config",
						Message:   "MySQL wait_timeout is too high",
						Details:   fmt.Sprintf("Current: %ds, Max: %ds", v, waitTimeoutMax),
						Timestamp: time.Now(),
					})
				}
			case "interactive_timeout":
				v, convErr := strconv.Atoi(val)
				if convErr == nil && v > waitTimeoutMax {
					findings = append(findings, alert.Finding{
						Severity:  alert.High,
						Check:     "perf_mysql_config",
						Message:   "MySQL interactive_timeout is too high",
						Details:   fmt.Sprintf("Current: %ds, Max: %ds", v, waitTimeoutMax),
						Timestamp: time.Now(),
					})
				}
			case "max_user_connections":
				if val == "0" {
					findings = append(findings, alert.Finding{
						Severity:  alert.Warning,
						Check:     "perf_mysql_config",
						Message:   "MySQL max_user_connections is unlimited",
						Details:   fmt.Sprintf("Current: 0 (unlimited), Recommended: %d", cfg.Performance.MySQLMaxConnectionsPerUser),
						Timestamp: time.Now(),
					})
				}
			case "slow_query_log":
				if strings.ToUpper(val) == "OFF" {
					findings = append(findings, alert.Finding{
						Severity:  alert.Warning,
						Check:     "perf_mysql_config",
						Message:   "MySQL slow query log is disabled",
						Details:   "Set slow_query_log=ON to help diagnose performance issues",
						Timestamp: time.Now(),
					})
				}
			}
		}
	}

	// --- InnoDB buffer pool hit ratio + temporary disk tables ---
	statusOut, err := runCmd("mysql", "-N", "-B", "-e",
		"SHOW GLOBAL STATUS WHERE Variable_name IN ('Innodb_buffer_pool_read_requests','Innodb_buffer_pool_reads','Created_tmp_disk_tables','Created_tmp_tables')")
	if err == nil && len(statusOut) > 0 {
		var readRequests, reads, tmpDiskTables, tmpTables int64
		for _, line := range strings.Split(string(statusOut), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			v, convErr := strconv.ParseInt(fields[1], 10, 64)
			if convErr != nil {
				continue
			}
			switch fields[0] {
			case "Innodb_buffer_pool_read_requests":
				readRequests = v
			case "Innodb_buffer_pool_reads":
				reads = v
			case "Created_tmp_disk_tables":
				tmpDiskTables = v
			case "Created_tmp_tables":
				tmpTables = v
			}
		}
		if tmpTables > 0 && tmpDiskTables > 0 {
			diskRatio := float64(tmpDiskTables) / float64(tmpTables) * 100
			if diskRatio > 25.0 {
				findings = append(findings, alert.Finding{
					Severity:  alert.Warning,
					Check:     "perf_mysql_config",
					Message:   "MySQL creating excessive temporary tables on disk",
					Details:   fmt.Sprintf("Disk ratio: %.1f%% (%d disk tables / %d total tables)", diskRatio, tmpDiskTables, tmpTables),
					Timestamp: time.Now(),
				})
			}
		}
		if readRequests > 0 {
			hitRatio := float64(readRequests-reads) / float64(readRequests) * 100
			if hitRatio < 95.0 {
				findings = append(findings, alert.Finding{
					Severity:  alert.High,
					Check:     "perf_mysql_config",
					Message:   "InnoDB buffer pool hit ratio is low",
					Details:   fmt.Sprintf("Hit ratio: %.1f%% (threshold: 95%%), disk reads: %d", hitRatio, reads),
					Timestamp: time.Now(),
				})
			}
		}
	}

	// --- Per-user connection counts ---
	plOut, err := runCmd("mysql", "-N", "-B", "-e", "SHOW PROCESSLIST")
	if err == nil && len(plOut) > 0 {
		userCounts := make(map[string]int)
		for _, line := range strings.Split(string(plOut), "\n") {
			fields := strings.Fields(line)
			// SHOW PROCESSLIST columns: Id, User, Host, db, Command, Time, State, Info
			if len(fields) < 2 {
				continue
			}
			user := fields[1]
			if user == "" || user == "User" {
				continue
			}
			userCounts[user]++
		}
		maxConn := cfg.Performance.MySQLMaxConnectionsPerUser
		for dbUser, count := range userCounts {
			if count > maxConn {
				findings = append(findings, alert.Finding{
					Severity:  alert.High,
					Check:     "perf_mysql_config",
					Message:   fmt.Sprintf("MySQL user %s holding excessive connections", dbUser),
					Details:   fmt.Sprintf("Connections: %d, Threshold: %d", count, maxConn),
					Timestamp: time.Now(),
				})
			}
		}
	}

	return findings
}

// CheckRedisConfig inspects a local Redis instance for performance-impacting
// misconfigurations: unset maxmemory, noeviction policy, non-expiring keys,
// and an overly aggressive bgsave schedule for the dataset size.
func CheckRedisConfig(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}
	if !store.ShouldRunThrottled("perf_redis_config", 60) {
		return nil
	}

	// Locate redis-cli
	redisCLI := ""
	for _, candidate := range []string{"/usr/bin/redis-cli", "/usr/local/bin/redis-cli"} {
		if _, err := osFS.Stat(candidate); err == nil {
			redisCLI = candidate
			break
		}
	}
	if redisCLI == "" {
		return nil
	}

	var findings []alert.Finding

	// --- maxmemory ---
	maxMemOut, err := runCmd(redisCLI, "config", "get", "maxmemory")
	if err == nil && len(maxMemOut) > 0 {
		lines := strings.Fields(string(maxMemOut))
		// redis config get returns two tokens: key value
		if len(lines) >= 2 && lines[1] == "0" {
			findings = append(findings, alert.Finding{
				Severity:  alert.Critical,
				Check:     "perf_redis_config",
				Message:   "Redis maxmemory is not set",
				Details:   "maxmemory=0 means Redis will use all available system memory without bound",
				Timestamp: time.Now(),
			})
		}
	}

	// --- maxmemory-policy ---
	policyOut, err := runCmd(redisCLI, "config", "get", "maxmemory-policy")
	if err == nil && len(policyOut) > 0 {
		lines := strings.Fields(string(policyOut))
		if len(lines) >= 2 && strings.ToLower(lines[1]) == "noeviction" {
			findings = append(findings, alert.Finding{
				Severity:  alert.High,
				Check:     "perf_redis_config",
				Message:   "Redis maxmemory-policy is noeviction",
				Details:   "noeviction causes Redis to return errors when memory is full instead of evicting keys",
				Timestamp: time.Now(),
			})
		}
	}

	// --- Non-expiring keys ratio via keyspace ---
	keyspaceOut, err := runCmd(redisCLI, "info", "keyspace")
	if err == nil && len(keyspaceOut) > 0 {
		var totalKeys, totalExpires int64
		for _, line := range strings.Split(string(keyspaceOut), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "db") {
				continue
			}
			// format: db0:keys=123,expires=45,avg_ttl=...
			parts := strings.SplitN(line, ":", 2)
			if len(parts) < 2 {
				continue
			}
			for _, kv := range strings.Split(parts[1], ",") {
				kv = strings.TrimSpace(kv)
				kvParts := strings.SplitN(kv, "=", 2)
				if len(kvParts) != 2 {
					continue
				}
				v, convErr := strconv.ParseInt(kvParts[1], 10, 64)
				if convErr != nil {
					continue
				}
				switch kvParts[0] {
				case "keys":
					totalKeys += v
				case "expires":
					totalExpires += v
				}
			}
		}
		if totalKeys > 0 {
			nonExpiring := totalKeys - totalExpires
			ratio := float64(nonExpiring) / float64(totalKeys) * 100
			if ratio > 95.0 {
				findings = append(findings, alert.Finding{
					Severity:  alert.Warning,
					Check:     "perf_redis_config",
					Message:   "Redis has excessive non-expiring keys",
					Details:   fmt.Sprintf("Non-expiring: %d / %d total keys (%.1f%%)", nonExpiring, totalKeys, ratio),
					Timestamp: time.Now(),
				})
			}
		}
	}

	// --- bgsave interval vs dataset size ---
	saveOut, _ := runCmd(redisCLI, "config", "get", "save")
	infoOut, _ := runCmd(redisCLI, "info", "memory")

	var usedMemoryBytes int64
	if len(infoOut) > 0 {
		for _, line := range strings.Split(string(infoOut), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "used_memory:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					v, convErr := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
					if convErr == nil {
						usedMemoryBytes = v
					}
				}
				break
			}
		}
	}

	const gbBytes = 1024 * 1024 * 1024
	largeDatasetBytes := int64(cfg.Performance.RedisLargeDatasetGB) * gbBytes
	bgsaveMinInterval := cfg.Performance.RedisBgsaveMinInterval

	if usedMemoryBytes > largeDatasetBytes && len(saveOut) > 0 {
		// save config output: "save\n<seconds> <changes>\n<seconds> <changes>\n..."
		lines := strings.Split(string(saveOut), "\n")
		aggressiveSave := false
		for _, line := range lines {
			line = strings.TrimSpace(line)
			fields := strings.Fields(line)
			if len(fields) < 1 {
				continue
			}
			// Skip the "save" key line itself
			if fields[0] == "save" {
				continue
			}
			// Each remaining line is "<seconds> <changes>" or a combined token
			seconds, convErr := strconv.Atoi(fields[0])
			if convErr == nil && seconds < bgsaveMinInterval {
				aggressiveSave = true
				break
			}
		}
		if aggressiveSave {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "perf_redis_config",
				Message:  "Redis bgsave interval too aggressive for dataset size",
				Details: fmt.Sprintf(
					"Used memory: %s, Threshold: %s, Minimum safe bgsave interval: %ds",
					humanBytes(usedMemoryBytes),
					humanBytes(largeDatasetBytes),
					bgsaveMinInterval,
				),
				Timestamp: time.Now(),
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Performance check helpers (WP-specific)
// ---------------------------------------------------------------------------

// safeIdentifier returns true if s matches ^[a-zA-Z0-9_]+$ (non-empty).
// Used to reject values with shell metacharacters before use in commands/SQL.
var safeIdentRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

func safeIdentifier(s string) bool {
	return s != "" && safeIdentRe.MatchString(s)
}

// extractPHPDefine extracts the value argument from a PHP define() line:
//
//	define('KEY', 'value');   or   define("KEY", "value");
//
// It is distinct from extractDefine (dbscan.go) which requires a key parameter.
// Returns the empty string if no value can be extracted.
func extractPHPDefine(line string) string {
	// Trim whitespace and trailing semicolons/comments.
	line = strings.TrimSpace(line)
	// Find the opening parenthesis.
	parenIdx := strings.Index(line, "(")
	if parenIdx < 0 {
		return ""
	}
	inner := line[parenIdx+1:]
	// Strip closing paren and anything after.
	if closeIdx := strings.LastIndex(inner, ")"); closeIdx >= 0 {
		inner = inner[:closeIdx]
	}
	// inner is now like: 'KEY', 'value'  or  "KEY", "value"
	// Split on the first comma, ignoring the key part.
	commaIdx := strings.Index(inner, ",")
	if commaIdx < 0 {
		return ""
	}
	valuePart := strings.TrimSpace(inner[commaIdx+1:])
	if valuePart == "" {
		return ""
	}
	// Strip surrounding quotes (single or double) when present.
	q := valuePart[0]
	if q == '\'' || q == '"' {
		if len(valuePart) < 2 {
			return ""
		}
		end := strings.LastIndexByte(valuePart, q)
		if end <= 0 {
			return ""
		}
		return valuePart[1:end]
	}
	// Unquoted literal (boolean/number constant). Strip a trailing ); or
	// whitespace and return the bare token. Examples wp-config.php uses:
	//   define('DISABLE_WP_CRON', true);
	//   define('WP_DEBUG', false);
	//   define('WP_MEMORY_LIMIT', 256);
	for i, c := range valuePart {
		if c == ' ' || c == '\t' || c == ';' || c == ')' || c == ',' {
			return strings.TrimSpace(valuePart[:i])
		}
	}
	return strings.TrimSpace(valuePart)
}

// ---------------------------------------------------------------------------
// Subdirs to skip in recursive helpers.
// ---------------------------------------------------------------------------

var skipDirs = map[string]bool{
	"wp-admin":     true,
	"wp-content":   true,
	"wp-includes":  true,
	"cache":        true,
	"node_modules": true,
	"vendor":       true,
}

// ---------------------------------------------------------------------------
// CheckErrorLogBloat
// ---------------------------------------------------------------------------

// scanErrorLogs recursively walks dir up to maxDepth looking for error_log
// files larger than threshold bytes. Results are appended to *findings (capped
// at 20).
func scanErrorLogs(dir string, thresholdBytes int64, depth int, findings *[]alert.Finding) {
	if depth < 0 || len(*findings) >= 20 {
		return
	}

	entries, err := osFS.ReadDir(dir)
	if err != nil {
		return
	}

	for _, e := range entries {
		if len(*findings) >= 20 {
			return
		}
		name := e.Name()
		fullPath := filepath.Join(dir, name)

		if e.IsDir() {
			if skipDirs[name] {
				continue
			}
			scanErrorLogs(fullPath, thresholdBytes, depth-1, findings)
			continue
		}

		if name != "error_log" {
			continue
		}
		info, statErr := e.Info()
		if statErr != nil {
			continue
		}
		if info.Size() > thresholdBytes {
			*findings = append(*findings, alert.Finding{
				Severity:  alert.Warning,
				Check:     "perf_error_logs",
				Message:   fmt.Sprintf("Bloated error_log: %s", fullPath),
				Details:   fmt.Sprintf("Size: %s", humanBytes(info.Size())),
				Timestamp: time.Now(),
			})
		}
	}
}

// CheckErrorLogBloat walks configured web roots (default /home/*/public_html
// on cPanel) looking for error_log files that exceed the configured size
// threshold. Throttled to once every 60 minutes.
func CheckErrorLogBloat(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}
	if !store.ShouldRunThrottled("perf_error_logs", 60) {
		return nil
	}

	thresholdBytes := int64(cfg.Performance.ErrorLogWarnSizeMB) * 1024 * 1024

	homeDirs := ResolveWebRoots(cfg)

	var findings []alert.Finding
	for _, dir := range homeDirs {
		scanErrorLogs(dir, thresholdBytes, 3, &findings)
		if len(findings) >= 20 {
			break
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// CheckWPConfig
// ---------------------------------------------------------------------------

// parseMemoryLimit converts a PHP memory_limit string (e.g. "256M", "1G")
// to megabytes. Returns 0 if the value cannot be parsed.
func parseMemoryLimit(s string) int {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" || s == "-1" {
		return 0
	}
	suffix := s[len(s)-1]
	numStr := s
	mult := 1
	switch suffix {
	case 'K':
		numStr = s[:len(s)-1]
		v, err := strconv.Atoi(numStr)
		if err != nil {
			return 0
		}
		return v / 1024
	case 'M':
		numStr = s[:len(s)-1]
		mult = 1
	case 'G':
		numStr = s[:len(s)-1]
		mult = 1024
	}
	v, err := strconv.Atoi(numStr)
	if err != nil {
		return 0
	}
	return v * mult
}

// scanWPConfigs recursively searches dir (max depth) for wp-config.php files
// and checks WP_MEMORY_LIMIT and co-located config files for issues.
func scanWPConfigs(dir, account string, cfg *config.Config, depth int, findings *[]alert.Finding) {
	if depth < 0 {
		return
	}

	entries, err := osFS.ReadDir(dir)
	if err != nil {
		return
	}

	for _, e := range entries {
		name := e.Name()
		fullPath := filepath.Join(dir, name)

		if e.IsDir() {
			if skipDirs[name] {
				continue
			}
			scanWPConfigs(fullPath, account, cfg, depth-1, findings)
			continue
		}

		if name != "wp-config.php" {
			continue
		}

		// --- WP_MEMORY_LIMIT ---
		wpData, readErr := osFS.ReadFile(fullPath)
		if readErr == nil {
			for _, line := range strings.Split(string(wpData), "\n") {
				if strings.Contains(line, "WP_MEMORY_LIMIT") {
					val := extractPHPDefine(strings.TrimSpace(line))
					if mb := parseMemoryLimit(val); mb > cfg.Performance.WPMemoryLimitMaxMB {
						*findings = append(*findings, alert.Finding{
							Severity:  alert.Warning,
							Check:     "perf_wp_config",
							Message:   fmt.Sprintf("Excessive WP_MEMORY_LIMIT for %s", account),
							Details:   fmt.Sprintf("File: %s, Value: %s", fullPath, val),
							Timestamp: time.Now(),
						})
					}
					break
				}
			}
		}

		// --- Co-located PHP config files ---
		wpDir := filepath.Dir(fullPath)
		for _, cfgFile := range []string{".htaccess", "php.ini", ".user.ini"} {
			cfgPath := filepath.Join(wpDir, cfgFile)
			data, readErr2 := osFS.ReadFile(cfgPath)
			if readErr2 != nil {
				continue
			}
			// cPanel MultiPHP INI Editor writes .user.ini with a fixed
			// header and owns the file's content. Values inside a
			// cPanel-managed .user.ini (max_execution_time=0 for a
			// backup importer, display_errors=On for a staging account)
			// reflect operator choices made through the cPanel UI and
			// are not attacker actions. Suppress findings for this
			// file in that case — operators do not need alerts for
			// their own configuration. The suppression is scoped
			// strictly to .user.ini: the same signature in php.ini or
			// .htaccess is not authoritative (cPanel does not write
			// those files) and the scanner treats it normally.
			if cfgFile == ".user.ini" && isCpanelManagedUserIni(data) {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				// Skip comment lines
				if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
					continue
				}
				lc := strings.ToLower(trimmed)

				switch {
				case strings.Contains(lc, "max_execution_time"):
					// max_execution_time = 0  (or  php_value max_execution_time 0)
					parts := strings.FieldsFunc(trimmed, func(r rune) bool { return r == '=' || r == ' ' || r == '\t' })
					if len(parts) >= 2 && parts[len(parts)-1] == "0" {
						*findings = append(*findings, alert.Finding{
							Severity:  alert.High,
							Check:     "perf_wp_config",
							Message:   fmt.Sprintf("Unlimited max_execution_time for %s", account),
							Details:   fmt.Sprintf("File: %s, Value: 0", cfgPath),
							Timestamp: time.Now(),
						})
					}
				case strings.Contains(lc, "display_errors"):
					parts := strings.FieldsFunc(trimmed, func(r rune) bool { return r == '=' || r == ' ' || r == '\t' })
					if len(parts) >= 2 && strings.ToLower(parts[len(parts)-1]) == "on" {
						*findings = append(*findings, alert.Finding{
							Severity:  alert.Warning,
							Check:     "perf_wp_config",
							Message:   fmt.Sprintf("display_errors enabled in production for %s", account),
							Details:   fmt.Sprintf("File: %s, Value: On", cfgPath),
							Timestamp: time.Now(),
						})
					}
				}
			}
		}
	}
}

// CheckWPConfig scans /home/*/public_html (max depth 2) for wp-config.php
// files and reports excessive WP_MEMORY_LIMIT values, unlimited
// max_execution_time, and display_errors enabled in production.
// Throttled to once every 60 minutes.
func CheckWPConfig(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}
	if !store.ShouldRunThrottled("perf_wp_config", 60) {
		return nil
	}

	homeDirs := ResolveWebRoots(cfg)

	var findings []alert.Finding
	for _, dir := range homeDirs {
		scanWPConfigs(dir, accountFromPath(dir), cfg, 2, &findings)
	}
	return findings
}

// accountFromPath extracts a best-effort account name from a web root path.
// On cPanel (/home/USER/public_html) it returns USER. On other layouts it
// returns the parent directory name, or the final path component if there
// is no parent. Used for reporting only — never for authorization.
func accountFromPath(dir string) string {
	parts := strings.Split(dir, string(filepath.Separator))
	// cPanel shape: /home/<account>/public_html
	for i, p := range parts {
		if p == "home" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	// Generic shape: /var/www/<site>, /srv/http/<site>, etc.
	if len(parts) >= 2 && parts[len(parts)-1] != "" {
		return parts[len(parts)-2]
	}
	return filepath.Base(dir)
}

// ---------------------------------------------------------------------------
// CheckWPTransientBloat
// ---------------------------------------------------------------------------

// findWPTransients recursively searches dir for wp-config.php files and
// queries the WordPress database for bloated transients.
func findWPTransients(dir string, cfg *config.Config, warnBytes, critBytes int64, depth int, findings *[]alert.Finding) {
	if depth < 0 {
		return
	}

	entries, err := osFS.ReadDir(dir)
	if err != nil {
		return
	}

	for _, e := range entries {
		name := e.Name()
		fullPath := filepath.Join(dir, name)

		if e.IsDir() {
			if skipDirs[name] {
				continue
			}
			findWPTransients(fullPath, cfg, warnBytes, critBytes, depth-1, findings)
			continue
		}

		if name != "wp-config.php" {
			continue
		}

		info := parseWPConfig(fullPath)
		if info.dbName == "" || info.dbUser == "" {
			continue
		}

		// Apply default table prefix when not set.
		if info.tablePrefix == "" {
			info.tablePrefix = "wp_"
		}

		// Security: validate identifiers before use in SQL.
		if !safeIdentifier(info.dbName) || !safeIdentifier(info.dbUser) || !safeIdentifier(info.tablePrefix) {
			continue
		}

		query := fmt.Sprintf(
			"SELECT option_name, LENGTH(option_value) as size FROM %soptions WHERE option_name LIKE '_transient_%%' AND LENGTH(option_value) > %d ORDER BY size DESC LIMIT 5",
			info.tablePrefix,
			warnBytes,
		)

		args := []string{
			"-N", "-B",
			"-h", info.dbHost,
			"-u", info.dbUser,
			info.dbName,
			"-e", query,
		}

		out, runErr := runCmdWithEnv("mysql", args, "MYSQL_PWD="+info.dbPass)
		if runErr != nil || len(out) == 0 {
			continue
		}

		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			optionName := fields[0]
			sizeBytes, convErr := strconv.ParseInt(fields[1], 10, 64)
			if convErr != nil {
				continue
			}

			var sev alert.Severity
			switch {
			case sizeBytes > critBytes:
				sev = alert.High
			case sizeBytes > warnBytes:
				sev = alert.Warning
			default:
				continue
			}

			*findings = append(*findings, alert.Finding{
				Severity:  sev,
				Check:     "perf_wp_transients",
				Message:   fmt.Sprintf("Bloated transient %s in %s", optionName, info.dbName),
				Details:   fmt.Sprintf("Size: %s", humanBytes(sizeBytes)),
				Timestamp: time.Now(),
			})
		}
	}
}

// CheckWPTransientBloat scans configured web roots (default /home/*/public_html
// on cPanel) for WordPress installs and queries each database for oversized
// transients. DB credentials are read from wp-config.php; the password is
// passed via MYSQL_PWD environment variable (never on the command line).
// Throttled to once every 60 minutes.
func CheckWPTransientBloat(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}
	if !store.ShouldRunThrottled("perf_wp_transients", 60) {
		return nil
	}

	warnBytes := int64(cfg.Performance.WPTransientWarnMB) * 1024 * 1024
	critBytes := int64(cfg.Performance.WPTransientCriticalMB) * 1024 * 1024

	homeDirs := ResolveWebRoots(cfg)

	var findings []alert.Finding
	for _, dir := range homeDirs {
		findWPTransients(dir, cfg, warnBytes, critBytes, 2, &findings)
	}
	return findings
}

// ---------------------------------------------------------------------------
// CheckWPCron
// ---------------------------------------------------------------------------

// scanWPCron recursively searches dir for wp-config.php files and checks
// whether DISABLE_WP_CRON is defined and set to true.
func scanWPCron(dir, account string, depth int, findings *[]alert.Finding) {
	if depth < 0 || len(*findings) >= 30 {
		return
	}

	entries, err := osFS.ReadDir(dir)
	if err != nil {
		return
	}

	for _, e := range entries {
		if len(*findings) >= 30 {
			return
		}
		name := e.Name()
		fullPath := filepath.Join(dir, name)

		if e.IsDir() {
			if skipDirs[name] {
				continue
			}
			scanWPCron(fullPath, account, depth-1, findings)
			continue
		}

		if name != "wp-config.php" {
			continue
		}

		data, readErr := osFS.ReadFile(fullPath)
		if readErr != nil {
			continue
		}

		defined := false
		enabled := false // true when defined as true

		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.Contains(trimmed, "DISABLE_WP_CRON") {
				continue
			}
			val := strings.ToLower(extractPHPDefine(trimmed))
			defined = true
			if val == "true" || val == "1" {
				enabled = true
			}
			break
		}

		if !defined || !enabled {
			*findings = append(*findings, alert.Finding{
				Severity: alert.Warning,
				Check:    "perf_wp_cron",
				Message:  fmt.Sprintf("WP-Cron not disabled for %s", account),
				Details: fmt.Sprintf(
					"File: %s - add define('DISABLE_WP_CRON', true); and use a real cron job instead",
					fullPath,
				),
				Timestamp: time.Now(),
			})
		}
	}
}

// CheckWPCron scans configured web roots (default /home/*/public_html on
// cPanel) for WordPress installs that have not disabled the built-in
// WP-Cron mechanism. Running WP-Cron via HTTP is a common cause of high
// load on busy sites.
// Throttled to once every 60 minutes.
func CheckWPCron(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}
	if !store.ShouldRunThrottled("perf_wp_cron", 60) {
		return nil
	}

	homeDirs := ResolveWebRoots(cfg)

	var findings []alert.Finding
	for _, dir := range homeDirs {
		scanWPCron(dir, accountFromPath(dir), 2, &findings)
		if len(findings) >= 30 {
			break
		}
	}
	return findings
}
