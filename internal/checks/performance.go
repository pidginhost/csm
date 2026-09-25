package checks

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mysqlclient"
	"github.com/pidginhost/csm/internal/redisinfo"
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

const (
	maxInt64Value  = int64(1<<63 - 1)
	maxUint64Value = ^uint64(0)
)

// uint64ToInt64Clamped narrows a uint64 to int64 for byte display.
func uint64ToInt64Clamped(v uint64) int64 {
	if v > uint64(maxInt64Value) {
		return maxInt64Value
	}
	return int64(v)
}

func redisLargeDatasetThresholdBytes(gb int) uint64 {
	if gb <= 0 {
		return 0
	}
	const gbBytes uint64 = 1024 * 1024 * 1024
	thresholdGB := uint64(gb)
	if thresholdGB > maxUint64Value/gbBytes {
		return maxUint64Value
	}
	return thresholdGB * gbBytes
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

func kibToDisplayBytes(kib uint64) int64 {
	const maxKiBForInt64Bytes = uint64(maxInt64Value / 1024)
	if kib > maxKiBForInt64Bytes {
		return maxInt64Value
	}
	return int64(kib) * 1024
}

// CheckLoadAverage compares load averages against per-core thresholds
// from config. The 1-minute load drives the Critical / High findings;
// when 1-minute is below the High threshold we additionally check the
// 5- and 15-minute averages for sustained pressure (>= 0.7 * High
// threshold on both) and emit a Warning. The sustained variant catches
// "constant 22%-of-cores busy for 15 minutes" which is invisible to a
// 1-minute spike check but is what operators actually want to see.
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

	switch {
	case load1 > critThreshold:
		return []alert.Finding{{
			Severity: alert.Critical,
			Check:    "perf_load",
			Message:  "High load average exceeds critical threshold",
			Details: fmt.Sprintf("Load: %.1f/%.1f/%.1f, Cores: %d, Threshold: %.1f",
				loads[0], loads[1], loads[2], cores, critThreshold),
			Timestamp: time.Now(),
		}}
	case load1 > highThreshold:
		return []alert.Finding{{
			Severity: alert.High,
			Check:    "perf_load",
			Message:  "High load average exceeds high threshold",
			Details: fmt.Sprintf("Load: %.1f/%.1f/%.1f, Cores: %d, Threshold: %.1f",
				loads[0], loads[1], loads[2], cores, highThreshold),
			Timestamp: time.Now(),
		}}
	}

	// Sustained pressure: 1-minute is calm but 5- and 15-minute
	// averages are both above 70% of the High threshold. This is the
	// "load 9 on 40 cores for 15 minutes" shape -- below the spike
	// threshold but a real operator concern.
	sustainedThreshold := highThreshold * 0.7
	if loads[1] > sustainedThreshold && loads[2] > sustainedThreshold {
		return []alert.Finding{{
			Severity: alert.Warning,
			Check:    "perf_load",
			Message:  "Sustained load (5m + 15m) above 70% of high threshold",
			Details: fmt.Sprintf("Load: %.1f/%.1f/%.1f, Cores: %d, Sustained threshold: %.1f",
				loads[0], loads[1], loads[2], cores, sustainedThreshold),
			Timestamp: time.Now(),
		}}
	}
	return nil
}

// phpWorkersByUser walks /proc and returns, per username, the cmdline samples
// of that user's live PHP web-worker processes. Instantaneous snapshot; callers that
// need a count use len(result[user]).
func phpWorkersByUser() map[string][]string {
	cmdlinePaths, _ := osFS.Glob("/proc/[0-9]*/cmdline")
	userProcs := make(map[string][]string)
	for _, cmdPath := range cmdlinePaths {
		pid := filepath.Base(filepath.Dir(cmdPath))

		data, err := osFS.ReadFile(cmdPath)
		if err != nil {
			continue
		}
		cmdStr := strings.ReplaceAll(string(data), "\x00", " ")
		cmdStr = strings.TrimSpace(cmdStr)
		safeCmdStr := redactProcCommandLine(data)

		if !isPHPWorkerCommand(cmdStr) {
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

		username := uidStringToUser(uid)
		userProcs[username] = append(userProcs[username], safeCmdStr)
	}
	return userProcs
}

func isPHPWorkerCommand(command string) bool {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}
	name := strings.TrimSuffix(strings.ToLower(filepath.Base(fields[0])), ":")
	return isVersionedPHPWorkerBinary(name, "lsphp") ||
		isVersionedPHPWorkerBinary(name, "php-cgi") ||
		isVersionedPHPWorkerBinary(name, "php-fpm")
}

func isVersionedPHPWorkerBinary(name, base string) bool {
	if name == base {
		return true
	}
	suffix := strings.TrimPrefix(name, base)
	if suffix == name || suffix == "" || suffix[0] < '0' || suffix[0] > '9' {
		return false
	}
	for _, char := range suffix {
		if (char < '0' || char > '9') && char != '.' {
			return false
		}
	}
	return suffix[len(suffix)-1] != '.'
}

// CheckPHPProcessLoad scans /proc for PHP web workers, groups them by user,
// and fires Critical if total exceeds cores*multiplier, High per user if
// individual count exceeds threshold.
func CheckPHPProcessLoad(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}

	cores := getCPUCores()

	userProcs := phpWorkersByUser()
	total := 0
	for _, procs := range userProcs {
		total += len(procs)
	}

	if total == 0 {
		return nil
	}

	var findings []alert.Finding

	// Critical: total PHP worker count exceeds cores * multiplier
	critTotalThreshold := cores * cfg.Performance.PHPProcessCriticalTotalMult
	if total > critTotalThreshold {
		findings = append(findings, alert.Finding{
			Severity:  alert.Critical,
			Check:     "perf_php_processes",
			Message:   "Total PHP worker process count exceeds critical threshold",
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
				Message:   fmt.Sprintf("Excessive PHP worker processes for user %s", username),
				Details:   fmt.Sprintf("Count: %d, Threshold: %d, Sample cmdlines: %s", len(procs), cfg.Performance.PHPProcessWarnPerUser, alert.RedactCommandLine(strings.Join(samples, " | "))),
				Timestamp: time.Now(),
			})
		}
	}

	return findings
}

// CheckSwapAndOOM checks for OOM killer events in dmesg and elevated swap
// usage from /proc/meminfo. Host OOM is Critical, cgroup OOM Warning, and
// swap usage above 50% High.
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
		seen := make(map[string]bool)
		for _, line := range strings.Split(string(dmesgOut), "\n") {
			lower := strings.ToLower(line)
			if !strings.Contains(lower, "out of memory") && !strings.Contains(lower, "oom_reaper") {
				continue
			}
			// Both the ISO and the -T fallback are filtered to the last
			// hour. A line whose timestamp cannot be parsed is skipped, not
			// reported: an OOM event we cannot date is exactly the stale
			// finding that previously fired a Critical on every scan.
			when, ok := parseDmesgOOMTime(line, useISO)
			if !ok || when.Before(cutoff) {
				continue
			}
			key := oomDedupKey(line)
			if seen[key] {
				continue
			}
			seen[key] = true
			severity, accountScoped := classifyOOMLine(line)
			message := "OOM killer invoked in the last hour"
			if accountScoped {
				message = "Account memory limit reached in the last hour"
			}
			findings = append(findings, alert.Finding{
				Severity: severity,
				Check:    "perf_memory",
				Message:  message,
				Details:  strings.TrimSpace(line),
				// Every kill logs a fresh pid and byte counts; keying dedup on
				// the victim process name keeps an ongoing OOM loop to one
				// finding per state-expiry window instead of one per scan.
				DedupKey:  key,
				Timestamp: time.Now(),
			})
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
				Details:  fmt.Sprintf("Swap used: %s / %s (%.0f%%)", humanBytes(kibToDisplayBytes(swapUsed)), humanBytes(kibToDisplayBytes(swapTotal)), usagePct),
				// The percentage moves every scan; without a pinned identity
				// each drift re-alerts the same sustained condition.
				DedupKey:  "swap_high",
				Timestamp: time.Now(),
			})
		}
	}

	return findings
}

// oomVictimProcess returns the killed process name from a dmesg OOM line
// ("... Killed process 2845662 (lsphp) ..."), or "host" when the line names
// no victim, so the dedup identity always has a stable value. Parenthesized
// OOM context before the process marker must not be mistaken for the victim.
func oomVictimProcess(line string) string {
	for _, marker := range []string{"Killed process ", "reaped process "} {
		markerIdx := strings.Index(line, marker)
		if markerIdx < 0 {
			continue
		}
		rest := line[markerIdx+len(marker):]
		pidEnd := strings.IndexAny(rest, " \t")
		if pidEnd <= 0 {
			continue
		}
		if _, err := strconv.ParseUint(rest[:pidEnd], 10, 64); err != nil {
			continue
		}
		rest = strings.TrimLeft(rest[pidEnd:], " \t")
		if len(rest) < 3 || rest[0] != '(' {
			continue
		}
		closeIdx := strings.IndexByte(rest[1:], ')')
		if closeIdx <= 0 {
			continue
		}
		if process := strings.TrimSpace(rest[1 : closeIdx+1]); process != "" {
			return process
		}
	}
	return "host"
}

// classifyOOMLine separates a host-wide OOM from a cgroup one. On a shared
// host a cgroup kill is an account reaching the memory limit its plan sets:
// routine, and not evidence about host health. Only real memory exhaustion is
// Critical, or the two become indistinguishable in the alert stream.
func classifyOOMLine(line string) (alert.Severity, bool) {
	if strings.Contains(strings.ToLower(line), "memory cgroup out of memory") {
		return alert.Warning, true
	}
	return alert.Critical, false
}

// oomDedupKey keeps the account-scoped and host-wide cases on separate dedup
// identities, so one account repeatedly hitting its limit cannot suppress the
// host-wide alert that follows it.
func oomDedupKey(line string) string {
	if _, accountScoped := classifyOOMLine(line); accountScoped {
		return "oom:cgroup:" + oomVictimProcess(line)
	}
	return "oom:host:" + oomVictimProcess(line)
}

// parseDmesgOOMTime extracts the event time from a dmesg line. ISO lines
// (--time-format iso) carry an absolute timestamp with a timezone offset as
// the first field. The -T fallback carries a bracketed ctime in local time
// ("[Mon Jan _2 15:04:05 2006] ..."). Returns ok=false when no timestamp can
// be parsed, so the caller drops the line rather than reporting an undatable
// (and therefore possibly stale) OOM event.
func parseDmesgOOMTime(line string, useISO bool) (time.Time, bool) {
	if useISO {
		// 2006-01-02T15:04:05,000000+0300 -- comma decimal, first field.
		ts := strings.Replace(strings.SplitN(line, " ", 2)[0], ",", ".", 1)
		for _, layout := range []string{"2006-01-02T15:04:05.000000-0700", "2006-01-02T15:04:05.000000-07:00"} {
			if parsed, err := time.Parse(layout, ts); err == nil {
				return parsed, true
			}
		}
		return time.Time{}, false
	}

	open := strings.IndexByte(line, '[')
	closeIdx := strings.IndexByte(line, ']')
	if open != 0 || closeIdx <= open {
		return time.Time{}, false
	}
	// dmesg -T prints local wall-clock time with no zone, so parse in Local.
	parsed, err := time.ParseInLocation("Mon Jan _2 15:04:05 2006", strings.TrimSpace(line[open+1:closeIdx]), time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

// CheckPHPHandler detects PHP CGI handler usage on LiteSpeed servers.
// On LiteSpeed, CGI is significantly slower than LSAPI; this check fires
// a Critical finding for each PHP version using the CGI handler.
func CheckPHPHandler(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
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
func CheckMySQLConfig(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}

	var findings []alert.Finding

	// --- Global variables ---
	varRows, err := mysqlclient.RootQuery(ctx,
		"SHOW GLOBAL VARIABLES WHERE Variable_name IN ('join_buffer_size','wait_timeout','interactive_timeout','max_user_connections','slow_query_log')")
	varOut := []byte(strings.Join(varRows, "\n"))
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
	statusRows, err := mysqlclient.RootQuery(ctx,
		"SHOW GLOBAL STATUS WHERE Variable_name IN ('Innodb_buffer_pool_read_requests','Innodb_buffer_pool_reads','Created_tmp_disk_tables','Created_tmp_tables')")
	statusOut := []byte(strings.Join(statusRows, "\n"))
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
	plRows, err := mysqlclient.RootQuery(ctx, "SHOW PROCESSLIST")
	if err == nil && len(plRows) > 0 {
		userCounts := make(map[string]int)
		for _, line := range plRows {
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
func CheckRedisConfig(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}

	// Skip on hosts without a local redis: peek at the redisinfo
	// client by trying a fast INFO server. Any error short-circuits
	// the whole check (matches the historical behaviour where a
	// missing redis-cli binary made every redis check a no-op).
	if _, _, err := redisinfo.MemoryUsage(ctx); err != nil {
		return nil
	}

	var findings []alert.Finding

	// --- maxmemory ---
	if maxMem, err := redisinfo.ConfigGet(ctx, "maxmemory"); err == nil && maxMem == "0" {
		findings = append(findings, alert.Finding{
			Severity:  alert.Critical,
			Check:     "perf_redis_config",
			Message:   "Redis maxmemory is not set",
			Details:   "maxmemory=0 means Redis will use all available system memory without bound",
			Timestamp: time.Now(),
		})
	}

	// --- maxmemory-policy ---
	policy, policyErr := redisinfo.ConfigGet(ctx, "maxmemory-policy")
	policyLower := ""
	if policyErr == nil {
		policyLower = strings.ToLower(strings.TrimSpace(policy))
	}
	if policyLower == "noeviction" {
		findings = append(findings, alert.Finding{
			Severity:  alert.High,
			Check:     "perf_redis_config",
			Message:   "Redis maxmemory-policy is noeviction",
			Details:   "noeviction causes Redis to return errors when memory is full instead of evicting keys",
			Timestamp: time.Now(),
		})
	}

	// --- Non-expiring keys ratio via keyspace ---
	// A high non-expiring ratio only breaks eviction under volatile-* policies
	// (which evict keys carrying a TTL) or noeviction. Under allkeys-* Redis
	// evicts any key, so non-expiring keys are reclaimable and the ratio is
	// benign.
	if stats, err := redisinfo.KeyspaceStats(ctx); err == nil && stats.TotalKeys > 0 && !strings.HasPrefix(policyLower, "allkeys-") {
		nonExpiring := stats.TotalKeys - stats.TotalExpires
		ratio := float64(nonExpiring) / float64(stats.TotalKeys) * 100
		if ratio > 95.0 {
			details := fmt.Sprintf("Non-expiring: %d / %d total keys (%.1f%%); %s",
				nonExpiring, stats.TotalKeys, ratio, redisNonExpiringPolicyDetail(policyLower))
			findings = append(findings, alert.Finding{
				Severity:  alert.Warning,
				Check:     "perf_redis_config",
				Message:   "Redis has excessive non-expiring keys",
				Details:   details,
				Timestamp: time.Now(),
			})
		}
	}

	// --- bgsave interval vs dataset size ---
	saveSpec, _ := redisinfo.ConfigGet(ctx, "save")
	usedBytes, _, _ := redisinfo.MemoryUsage(ctx)

	largeDatasetBytes := redisLargeDatasetThresholdBytes(cfg.Performance.RedisLargeDatasetGB)
	bgsaveMinInterval := cfg.Performance.RedisBgsaveMinInterval

	if usedBytes > largeDatasetBytes && saveSpec != "" {
		// `CONFIG GET save` returns the spec as a single space-separated
		// string of alternating "<seconds> <changes>" pairs, e.g.
		// "900 1 300 10 60 10000". Walk the seconds tokens (every
		// other field) and flag any below the configured floor.
		fields := strings.Fields(saveSpec)
		aggressiveSave := false
		for i := 0; i < len(fields); i += 2 {
			seconds, convErr := strconv.Atoi(fields[i])
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
					humanBytes(uint64ToInt64Clamped(usedBytes)),
					humanBytes(uint64ToInt64Clamped(largeDatasetBytes)),
					bgsaveMinInterval,
				),
				Timestamp: time.Now(),
			})
		}
	}

	// --- used_memory vs maxmemory headroom ---
	// The maxmemory==0 branch above flags the unset case. When maxmemory
	// IS set, used/max ratio is the operator-meaningful signal: at 80%
	// the eviction policy is about to start churning hot keys; at 90%
	// noeviction-policy instances start returning OOM errors.
	_, maxBytes, _ := redisinfo.MemoryUsage(ctx)
	if maxBytes > 0 && usedBytes > 0 {
		pct := float64(usedBytes) / float64(maxBytes) * 100
		switch {
		case pct >= 90:
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "perf_redis_config",
				Message:  "Redis used memory >= 90% of maxmemory",
				Details: fmt.Sprintf(
					"Used: %s / Max: %s (%.1f%%)",
					humanBytes(uint64ToInt64Clamped(usedBytes)),
					humanBytes(uint64ToInt64Clamped(maxBytes)),
					pct,
				),
				Timestamp: time.Now(),
			})
		case pct >= 80:
			findings = append(findings, alert.Finding{
				Severity: alert.Warning,
				Check:    "perf_redis_config",
				Message:  "Redis used memory >= 80% of maxmemory",
				Details: fmt.Sprintf(
					"Used: %s / Max: %s (%.1f%%)",
					humanBytes(uint64ToInt64Clamped(usedBytes)),
					humanBytes(uint64ToInt64Clamped(maxBytes)),
					pct,
				),
				Timestamp: time.Now(),
			})
		}
	}

	return findings
}

func redisNonExpiringPolicyDetail(policyLower string) string {
	switch {
	case policyLower == "":
		return "maxmemory-policy is unavailable, so non-expiring keys may be unsafe under memory pressure"
	case policyLower == "noeviction":
		return "maxmemory-policy noeviction does not evict keys under memory pressure"
	case strings.HasPrefix(policyLower, "volatile-"):
		return fmt.Sprintf("maxmemory-policy %q only evicts keys with a TTL under memory pressure", policyLower)
	default:
		return fmt.Sprintf("maxmemory-policy %q may leave non-expiring keys unreclaimable under memory pressure", policyLower)
	}
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

const (
	errorLogFindingLimit = 20
	errorLogSizesKey     = "_perf_error_log_sizes"
	// errorLogMinRateSpan is the shortest span a growth rate is computed over.
	// A restart or manual rescan minutes after the last run would otherwise
	// extrapolate a few seconds of writes into a daily rate.
	errorLogMinRateSpan = time.Hour
)

var errorLogNow = time.Now

type bloatedErrorLog struct {
	path   string
	size   int64
	device uint64
	inode  uint64
}

// Size and Seen anchor the rate window; LastSize detects a shrink even when
// frequent scans have not yet advanced that window. Identity detects rotation.
type errorLogObservation struct {
	Size     int64  `json:"size"`
	Seen     int64  `json:"seen"`
	LastSize int64  `json:"last_size"`
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
}

// errorLogScan collects bloated logs and the paths the walk proved. Only a log
// with a saved baseline or one bloated now can carry a finding to retire, so
// coverage is recorded for those alone rather than for every directory walked.
type errorLogScan struct {
	logs    []bloatedErrorLog
	covered map[string]bool
	tracked map[string]bool
}

func (s *errorLogScan) observe(path string, info os.FileInfo, thresholdBytes int64) {
	bloated := info != nil && info.Mode().IsRegular() && info.Size() > thresholdBytes
	if !bloated && !s.tracked[path] {
		return
	}
	if s.covered == nil {
		s.covered = make(map[string]bool)
	}
	s.covered[path] = true
	if !bloated {
		return
	}
	identity, _ := selfWriteIdentityFromFileInfo(info)
	s.logs = append(s.logs, bloatedErrorLog{
		path: path, size: info.Size(), device: identity.Device, inode: identity.Inode,
	})
}

// Heavy trees are not descended, but their immediate error_log is checked.
// A tracked log found small or missing is recorded as covered, so a partial
// scan can retire its finding without discarding evidence from unreadable
// paths.
func scanErrorLogs(ctx context.Context, dir string, thresholdBytes int64, depth int, roots map[string]struct{}, scan *errorLogScan) bool {
	if ctx.Err() != nil {
		return false
	}
	if depth < 0 {
		return true
	}
	entries, err := osFS.ReadDir(dir)
	if err != nil {
		return errors.Is(err, fs.ErrNotExist)
	}
	complete, sawLog := true, false
	for _, e := range entries {
		if ctx.Err() != nil {
			return false
		}
		name := e.Name()
		fullPath := filepath.Join(dir, name)
		if name == "error_log" {
			sawLog = true
			info, infoErr := e.Info()
			switch {
			case infoErr == nil:
				scan.observe(fullPath, info, thresholdBytes)
			case errors.Is(infoErr, fs.ErrNotExist):
				scan.observe(fullPath, nil, thresholdBytes)
			default:
				complete = false
			}
		}
		if !e.IsDir() || depth == 0 {
			continue
		}
		if _, ownRoot := roots[fullPath]; ownRoot {
			continue
		}
		if skipDirs[name] {
			path := filepath.Join(fullPath, "error_log")
			info, statErr := osFS.Lstat(path)
			switch {
			case statErr == nil:
				scan.observe(path, info, thresholdBytes)
			case errors.Is(statErr, fs.ErrNotExist):
				scan.observe(path, nil, thresholdBytes)
			default:
				complete = false
			}
			continue
		}
		if !scanErrorLogs(ctx, fullPath, thresholdBytes, depth-1, roots, scan) {
			complete = false
		}
	}
	if !sawLog {
		scan.observe(filepath.Join(dir, "error_log"), nil, thresholdBytes)
	}
	return complete
}

// CheckErrorLogBloat walks the configured web roots and every docroot in
// cPanel's domain map looking for error_log files over the warning size. Logs
// over the critical size are High so the operator is told; the rest only show
// on the Performance page. The largest logs are kept when the finding cap is
// reached. The runner enforces a 60-minute throttle via checkThrottleMin.
func CheckErrorLogBloat(ctx context.Context, cfg *config.Config, scanState *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}
	warnBytes := int64(cfg.Performance.ErrorLogWarnSizeMB) * 1024 * 1024
	critBytes := int64(cfg.Performance.ErrorLogCriticalSizeMB) * 1024 * 1024

	roots, complete := validatedDocrootSet(cfg)
	rootSet := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		rootSet[root.path] = struct{}{}
	}
	previous := loadErrorLogSizes(scanState)
	scan := errorLogScan{tracked: make(map[string]bool, len(previous))}
	for path := range previous {
		scan.tracked[path] = true
	}
	for _, root := range roots {
		if !scanErrorLogs(ctx, root.path, warnBytes, 3, rootSet, &scan) {
			complete = false
		}
	}
	if !complete {
		markCheckIncomplete(ctx, "perf_error_logs")
	}
	if ctx.Err() != nil {
		markCheckIncomplete(ctx, "perf_error_logs")
		return nil
	}

	sort.Slice(scan.logs, func(i, j int) bool {
		if scan.logs[i].size != scan.logs[j].size {
			return scan.logs[i].size > scan.logs[j].size
		}
		return scan.logs[i].path < scan.logs[j].path
	})
	now := errorLogNow()
	current := make(map[string]errorLogObservation, len(scan.logs))
	var findings []alert.Finding
	for i, log := range scan.logs {
		details, baseline := errorLogGrowth(log, previous[log.path], now)
		current[log.path] = baseline
		if i < errorLogFindingLimit {
			findings = append(findings, newErrorLogFinding(log, details, critBytes, now))
		}
	}
	for path, obs := range previous {
		if _, seen := current[path]; seen {
			continue
		}
		// Without the map, a nested root may be hidden behind an ancestor's
		// depth or directory exclusions. Only direct observations retire it.
		if complete || scan.covered[path] {
			scan.observe(path, nil, warnBytes)
		} else {
			current[path] = obs
		}
	}
	if ctx.Err() != nil {
		markCheckIncomplete(ctx, "perf_error_logs")
		return nil
	}
	scopes := make(map[string]bool, len(scan.covered))
	for path := range scan.covered {
		scopes[errorLogCoverageScope(path)] = true
	}
	recordCompletedCoverageScopes(ctx, "perf_error_logs", scopes)
	storeErrorLogSizes(scanState, current)
	return findings
}

// errorLogGrowth renders the finding details and returns the baseline to keep.
// A baseline younger than errorLogMinRateSpan keeps its rate anchor while
// tracking the latest size; a shrink or file replacement resets the anchor.
func errorLogGrowth(log bloatedErrorLog, prev errorLogObservation, now time.Time) (string, errorLogObservation) {
	details := fmt.Sprintf("Size: %s", humanBytes(log.size))
	fresh := errorLogObservation{
		Size: log.size, Seen: now.Unix(), LastSize: log.size, Device: log.device, Inode: log.inode,
	}
	if prev.Seen == 0 || prev.Inode != log.inode || prev.Device != log.device ||
		log.size < prev.Size || log.size < prev.LastSize || now.Unix() < prev.Seen {
		return details, fresh
	}
	span := now.Sub(time.Unix(prev.Seen, 0))
	if span < errorLogMinRateSpan {
		prev.LastSize = log.size
		return details, prev
	}
	perDay := int64(float64(log.size-prev.Size) * float64(24*time.Hour) / float64(span))
	if perDay > 0 {
		details += fmt.Sprintf(", growing %s/day", humanBytes(perDay))
	}
	return details, fresh
}

// newErrorLogFinding keys the finding on its path and tier, not its size, so
// a growing log stays one finding (one alert per day, a dismissal that
// sticks) while crossing into the critical tier is a new event.
func newErrorLogFinding(log bloatedErrorLog, details string, critBytes int64, now time.Time) alert.Finding {
	severity, tier := alert.Warning, "warning"
	if log.size > critBytes {
		severity, tier = alert.High, "critical"
	}
	return alert.Finding{
		Severity:      severity,
		Check:         "perf_error_logs",
		Message:       fmt.Sprintf("Bloated error_log: %s", log.path),
		Details:       details,
		DedupKey:      tier + ":" + log.path,
		CoverageScope: errorLogCoverageScope(log.path),
		Timestamp:     now,
	}
}

func errorLogCoverageScope(path string) string {
	return "error_log:" + path
}

func loadErrorLogSizes(scanState *state.Store) map[string]errorLogObservation {
	if scanState == nil {
		return nil
	}
	raw, ok := scanState.GetRaw(errorLogSizesKey)
	if !ok {
		return nil
	}
	var sizes map[string]errorLogObservation
	if json.Unmarshal([]byte(raw), &sizes) != nil {
		return nil
	}
	return sizes
}

// storeErrorLogSizes replaces the saved baselines, which drops any log that is
// gone or back under the warning size.
func storeErrorLogSizes(scanState *state.Store, sizes map[string]errorLogObservation) {
	if scanState == nil {
		return
	}
	if len(sizes) == 0 {
		if err := scanState.DeleteRawAndSave(errorLogSizesKey); err != nil {
			fmt.Fprintf(os.Stderr, "perf_error_logs: baseline clear: %v\n", err)
		}
		return
	}
	raw, err := json.Marshal(sizes)
	if err != nil {
		return
	}
	if err := scanState.SetRawAndSave(errorLogSizesKey, string(raw)); err != nil {
		fmt.Fprintf(os.Stderr, "perf_error_logs: baseline write: %v\n", err)
	}
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
// The runner enforces a 60-minute throttle via checkThrottleMin.
func CheckWPConfig(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
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

		rows, runErr := mysqlclient.PerAccountQuery(context.Background(), mysqlclient.Creds{
			User:     info.dbUser,
			Password: info.dbPass,
			Host:     info.dbHost,
			DBName:   info.dbName,
		}, query)
		if runErr != nil || len(rows) == 0 {
			continue
		}

		for _, line := range rows {
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
// The runner enforces a 60-minute throttle via checkThrottleMin.
func CheckWPTransientBloat(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
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

const (
	wpCronFindingLimit = 30
	wpCronCursorKey    = "_wpcron_scan_cursor"
)

var (
	wpCronTablePrefixAssignRe = regexp.MustCompile(`(?im)^[\t ]*\$table_prefix[\t ]*=`)
	wpCronRequireRe           = regexp.MustCompile(`(?im)^[\t ]*require(?:_once)?\b`)
)

type wpCronCandidate struct {
	path    string
	account string
}

type wpCronScanCursor struct {
	Root string `json:"root"`
	Path string `json:"path,omitempty"`
}

// scanWPCronCandidates recursively finds real WordPress installs. When a
// nested vhost is also a scan root, the broader root leaves that subtree to
// the more-specific root. This preserves the full depth allowance for both
// roots without reading or reporting the same install twice.
func scanWPCronCandidates(
	ctx context.Context,
	scanRoot, dir, account string,
	depth int,
	allRoots map[string]struct{},
	candidates map[string]wpCronCandidate,
) bool {
	if depth < 0 {
		return true
	}
	if ctx.Err() != nil {
		return false
	}
	cleanDir := filepath.Clean(dir)
	if cleanDir != filepath.Clean(scanRoot) {
		if _, nestedRoot := allRoots[cleanDir]; nestedRoot {
			return true
		}
	}

	entries, err := osFS.ReadDir(cleanDir)
	if err != nil {
		return errors.Is(err, fs.ErrNotExist)
	}
	complete := true
	for _, entry := range entries {
		if ctx.Err() != nil {
			return false
		}
		name := entry.Name()
		fullPath := filepath.Join(cleanDir, name)
		if entry.IsDir() {
			if skipDirs[name] {
				continue
			}
			if !scanWPCronCandidates(ctx, scanRoot, fullPath, account, depth-1, allRoots, candidates) {
				complete = false
			}
			continue
		}
		if name != "wp-config.php" || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			complete = false
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}

		data, readErr := osFS.ReadFile(fullPath)
		if readErr != nil {
			if !errors.Is(readErr, fs.ErrNotExist) {
				complete = false
			}
			continue
		}
		if wpCronHasActiveDisableDefine(data) {
			continue
		}
		isWordPress, validateErr := wpCronInstallIsValid(fullPath, data)
		if validateErr != nil {
			complete = false
			continue
		}
		if !isWordPress {
			continue
		}
		candidates[fullPath] = wpCronCandidate{path: fullPath, account: account}
	}
	return complete
}

// wpCronInstallIsValid requires both the WordPress bootstrap shape and the
// core files the remediation will invoke. A stray or backup wp-config.php is
// not enough evidence to edit customer data or install a crontab entry.
func wpCronInstallIsValid(configPath string, data []byte) (bool, error) {
	code := stripPHPCommentsFromCode(phpCodeOnly(string(data)))
	codeWithoutStrings := stripPHPStringsFromCode(code)
	if !wpCronTablePrefixAssignRe.MatchString(codeWithoutStrings) ||
		!wpCronHasSettingsRequire(code, codeWithoutStrings) {
		return false, nil
	}

	docroot := filepath.Dir(configPath)
	for _, name := range []string{"wp-settings.php", "wp-cron.php", "wp-load.php"} {
		info, err := osFS.Lstat(filepath.Join(docroot, name))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return false, nil
			}
			return false, err
		}
		if !info.Mode().IsRegular() {
			return false, nil
		}
	}
	for _, name := range []string{"wp-admin", "wp-includes"} {
		info, err := osFS.Lstat(filepath.Join(docroot, name))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return false, nil
			}
			return false, err
		}
		if !info.IsDir() {
			return false, nil
		}
	}
	return true, nil
}

// wpCronHasSettingsRequire ties the wp-settings.php literal to an active
// require statement. Looking for both tokens independently lets quoted sample
// text masquerade as a WordPress bootstrap and can trigger destructive fixes.
func wpCronHasSettingsRequire(code, codeWithoutStrings string) bool {
	for _, loc := range wpCronRequireRe.FindAllStringIndex(codeWithoutStrings, -1) {
		statementEnd := strings.IndexByte(codeWithoutStrings[loc[1]:], ';')
		if statementEnd < 0 {
			continue
		}
		statementEnd += loc[1]
		if strings.Contains(strings.ToLower(code[loc[0]:statementEnd]), "wp-settings.php") {
			return true
		}
	}
	return false
}

func sortedWPCronCandidates(candidates map[string]wpCronCandidate) []wpCronCandidate {
	out := make([]wpCronCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

func newWPCronFinding(candidate wpCronCandidate) alert.Finding {
	return alert.Finding{
		Severity: alert.Warning,
		Check:    "perf_wp_cron",
		Message:  fmt.Sprintf("WP-Cron not disabled for %s", candidate.account),
		Details: fmt.Sprintf(
			"File: %s - add define('DISABLE_WP_CRON', true); and use a real cron job instead",
			candidate.path,
		),
		Timestamp: time.Now(),
	}
}

// CheckWPCron scans configured web roots plus validated cPanel document roots
// for WordPress installs that have not disabled the built-in WP-Cron
// mechanism. Running WP-Cron via HTTP is a common cause of high load on busy
// sites.
// The runner enforces a 60-minute throttle via checkThrottleMin.
func CheckWPCron(ctx context.Context, cfg *config.Config, scanState *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}

	roots, rootsComplete := validatedDocrootSet(cfg)
	if !rootsComplete {
		markCheckIncomplete(ctx, "perf_wp_cron")
	}
	if len(roots) == 0 {
		clearWPCronCursor(scanState)
		return nil
	}

	allRoots := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		allRoots[root.path] = struct{}{}
	}
	cursor := loadWPCronCursor(scanState)
	start, resumeCurrent := wpCronStartRoot(roots, cursor)
	var findings []alert.Finding
	var nextCursor wpCronScanCursor
	capped := false
	for visited := 0; visited < len(roots); visited++ {
		if ctx.Err() != nil {
			return findings
		}
		root := roots[(start+visited)%len(roots)]
		candidates := make(map[string]wpCronCandidate)
		if !scanWPCronCandidates(ctx, root.path, root.path, root.account, 2, allRoots, candidates) {
			markCheckIncomplete(ctx, "perf_wp_cron")
		}
		sorted := sortedWPCronCandidates(candidates)
		lastPath := ""
		if visited == 0 && resumeCurrent && root.path == cursor.Root {
			lastPath = cursor.Path
		}
		first := sort.Search(len(sorted), func(i int) bool { return sorted[i].path > lastPath })
		eligible := sorted[first:]
		remaining := wpCronFindingLimit - len(findings)
		selected := len(eligible)
		if selected > remaining {
			selected = remaining
		}
		for _, candidate := range eligible[:selected] {
			findings = append(findings, newWPCronFinding(candidate))
		}
		if len(findings) == wpCronFindingLimit {
			nextCursor.Root = root.path
			if selected < len(eligible) {
				nextCursor.Path = eligible[selected-1].path
			}
			capped = true
			break
		}
	}
	if ctx.Err() != nil {
		return findings
	}
	if capped {
		storeWPCronCursor(scanState, nextCursor)
	} else {
		clearWPCronCursor(scanState)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Details < findings[j].Details })
	return findings
}

func loadWPCronCursor(scanState *state.Store) wpCronScanCursor {
	if scanState == nil {
		return wpCronScanCursor{}
	}
	raw, ok := scanState.GetRaw(wpCronCursorKey)
	if !ok {
		return wpCronScanCursor{}
	}
	var cursor wpCronScanCursor
	if json.Unmarshal([]byte(raw), &cursor) != nil {
		return wpCronScanCursor{}
	}
	return cursor
}

func wpCronStartRoot(roots []docrootScanRoot, cursor wpCronScanCursor) (start int, resume bool) {
	if cursor.Root == "" {
		return 0, false
	}
	if cursor.Path != "" {
		i := sort.Search(len(roots), func(i int) bool { return roots[i].path >= cursor.Root })
		if i < len(roots) && roots[i].path == cursor.Root {
			return i, true
		}
	}
	i := sort.Search(len(roots), func(i int) bool { return roots[i].path > cursor.Root })
	if i == len(roots) {
		i = 0
	}
	return i, false
}

func storeWPCronCursor(scanState *state.Store, cursor wpCronScanCursor) {
	if scanState == nil {
		return
	}
	raw, err := json.Marshal(cursor)
	if err != nil {
		return
	}
	if err := scanState.SetRawAndSave(wpCronCursorKey, string(raw)); err != nil {
		fmt.Fprintf(os.Stderr, "wpcron: cursor write: %v\n", err)
	}
}

func clearWPCronCursor(scanState *state.Store) {
	if scanState == nil {
		return
	}
	if err := scanState.DeleteRawAndSave(wpCronCursorKey); err != nil {
		fmt.Fprintf(os.Stderr, "wpcron: cursor clear: %v\n", err)
	}
}
