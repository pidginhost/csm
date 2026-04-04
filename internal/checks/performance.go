package checks

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
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
		f, err := os.Open("/proc/cpuinfo")
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

	data, err := os.ReadFile("/proc/loadavg")
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
// swap total, and swap free — all in kilobytes.
func parseMemInfo() (total, available, swapTotal, swapFree uint64) {
	f, err := os.Open("/proc/meminfo")
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
func CheckLoadAverage(cfg *config.Config, _ *state.Store) []alert.Finding {
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
func CheckPHPProcessLoad(cfg *config.Config, _ *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}

	cores := getCPUCores()

	// pid → list of cmdline strings for that pid
	type procInfo struct {
		uid     string
		cmdline string
	}

	cmdlinePaths, _ := filepath.Glob("/proc/[0-9]*/cmdline")

	// user → list of cmdline samples
	userProcs := make(map[string][]string)
	total := 0

	for _, cmdPath := range cmdlinePaths {
		pid := filepath.Base(filepath.Dir(cmdPath))

		data, err := os.ReadFile(cmdPath)
		if err != nil {
			continue
		}
		cmdStr := strings.ReplaceAll(string(data), "\x00", " ")
		cmdStr = strings.TrimSpace(cmdStr)

		if !strings.Contains(cmdStr, "lsphp") {
			continue
		}

		// Read UID from status
		statusData, _ := os.ReadFile(filepath.Join("/proc", pid, "status"))
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
func CheckSwapAndOOM(cfg *config.Config, _ *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}

	var findings []alert.Finding

	// Check dmesg for OOM events
	dmesgOut, err := runCmd("dmesg", "--level=err", "-T")
	if err == nil && dmesgOut != nil {
		for _, line := range strings.Split(string(dmesgOut), "\n") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "out of memory") || strings.Contains(lower, "oom_reaper") {
				findings = append(findings, alert.Finding{
					Severity:  alert.Critical,
					Check:     "perf_memory",
					Message:   "OOM killer invoked in the last hour",
					Details:   strings.TrimSpace(line),
					Timestamp: time.Now(),
				})
				break // one finding is enough
			}
		}
	}

	// Check swap usage
	_, _, swapTotal, swapFree := parseMemInfo()
	if swapTotal > 0 {
		swapUsed := swapTotal - swapFree
		usagePct := float64(swapUsed) / float64(swapTotal) * 100

		if usagePct > 50 {
			findings = append(findings, alert.Finding{
				Severity:  alert.High,
				Check:     "perf_memory",
				Message:   "High swap usage",
				Details:   fmt.Sprintf("Swap used: %s / %s (%.0f%%)", humanBytes(int64(swapUsed)*1024), humanBytes(int64(swapTotal)*1024), usagePct),
				Timestamp: time.Now(),
			})
		}
	}

	return findings
}
