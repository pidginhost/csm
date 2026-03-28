//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/checks"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/signatures"
	"github.com/pidginhost/cpanel-security-monitor/internal/yara"
)

// fanotify constants (not all in Go stdlib)
const (
	FAN_MARK_ADD    = 0x00000001
	FAN_MARK_MOUNT  = 0x00000010
	FAN_CLOSE_WRITE = 0x00000008
	FAN_CREATE      = 0x00000100
	FAN_CLASS_NOTIF = 0x00000000
	FAN_CLOEXEC     = 0x00000001
	FAN_NONBLOCK    = 0x00000002
)

// fanotifyEventMetadata is the header for each fanotify event.
type fanotifyEventMetadata struct {
	EventLen    uint32
	Vers        uint8
	Reserved    uint8
	MetadataLen uint16
	Mask        uint64
	Fd          int32
	Pid         int32
}

const metadataSize = int(unsafe.Sizeof(fanotifyEventMetadata{}))

// M1 — webshells map at package level (avoid per-call allocation)
var knownWebshells = map[string]bool{
	"h4x0r.php": true, "c99.php": true, "r57.php": true,
	"wso.php": true, "alfa.php": true, "b374k.php": true,
	"shell.php": true, "cmd.php": true, "backdoor.php": true,
	"webshell.php": true,
}

// M3 — plugin stat cache with TTL
type pluginCacheEntry struct {
	exists bool
	ts     time.Time
}

var pluginStatCache sync.Map // key: pluginDir string → value: pluginCacheEntry

const pluginCacheTTL = 5 * time.Minute

// FileMonitor watches mount points for file creation/modification using fanotify.
type FileMonitor struct {
	fd         int
	cfg        *config.Config
	alertCh    chan<- alert.Finding
	analyzerCh chan fileEvent

	// M7 — separate counters for dropped events and alerts
	droppedEvents int64
	droppedAlerts int64

	// C4 — pipe for epoll stop signaling
	pipeFds    [2]int // [0]=read, [1]=write
	pipeClosed int32  // atomic flag: 1 = pipe fds closed by drainAndClose

	// C2 — sync.Once for safe Stop
	stopOnce  sync.Once
	drainOnce sync.Once
	stopCh    chan struct{} // internal stop channel
	wg        sync.WaitGroup
}

type fileEvent struct {
	path string
	fd   int
}

// NewFileMonitor creates a fanotify-based file monitor.
// Returns error if the kernel doesn't support the required features.
func NewFileMonitor(cfg *config.Config, alertCh chan<- alert.Finding) (*FileMonitor, error) {
	// H1 — use golang.org/x/sys/unix for fanotify_init
	fd, err := unix.FanotifyInit(FAN_CLASS_NOTIF|FAN_CLOEXEC|FAN_NONBLOCK, unix.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w (kernel may not support fanotify)", err)
	}

	// Mark mount points; M2 — track successful mounts
	mountPaths := []string{"/home", "/tmp", "/dev/shm"}
	mountOK := 0
	for _, path := range mountPaths {
		// H1 — use golang.org/x/sys/unix for fanotify_mark
		err = unix.FanotifyMark(fd, FAN_MARK_ADD|FAN_MARK_MOUNT, FAN_CLOSE_WRITE|FAN_CREATE, -1, path)
		if err != nil {
			// Try without FAN_CREATE (older kernels)
			err = unix.FanotifyMark(fd, FAN_MARK_ADD|FAN_MARK_MOUNT, FAN_CLOSE_WRITE, -1, path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s] Warning: cannot watch %s: %v\n", ts(), path, err)
				continue
			}
		}
		mountOK++
	}

	// M2 — error on zero successful mounts
	if mountOK == 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("no mount points could be watched (tried %v)", mountPaths)
	}

	// C4 — create pipe for epoll stop signaling
	var pipeFds [2]int
	if err := unix.Pipe2(pipeFds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("pipe2: %w", err)
	}

	fm := &FileMonitor{
		fd:         fd,
		cfg:        cfg,
		alertCh:    alertCh,
		analyzerCh: make(chan fileEvent, 1000),
		pipeFds:    pipeFds,
		stopCh:     make(chan struct{}),
	}

	return fm, nil
}

// Run starts the file monitor event loop and analyzer workers.
func (fm *FileMonitor) Run(stopCh <-chan struct{}) {
	// H7 — configurable workers: min 4, max 16, based on NumCPU
	numWorkers := runtime.NumCPU()
	if numWorkers < 4 {
		numWorkers = 4
	}
	if numWorkers > 16 {
		numWorkers = 16
	}

	for i := 0; i < numWorkers; i++ {
		fm.wg.Add(1)
		go fm.analyzerWorker()
	}

	// Start overflow reporter
	fm.wg.Add(1)
	go fm.overflowReporter()

	// C4 — create epoll instance, watch fanotify fd + pipe read end
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] epoll_create1 failed: %v, falling back to poll loop\n", ts(), err)
		fm.runPollFallback(stopCh)
		return
	}
	defer func() { _ = unix.Close(epfd) }()

	// Add fanotify fd to epoll
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fm.fd, &unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(fm.fd),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] epoll_ctl(fanotify): %v\n", ts(), err)
		fm.runPollFallback(stopCh)
		return
	}

	// Add pipe read end to epoll (for stop signaling)
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fm.pipeFds[0], &unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(fm.pipeFds[0]),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] epoll_ctl(pipe): %v\n", ts(), err)
		fm.runPollFallback(stopCh)
		return
	}

	// Forward external stopCh to our internal mechanism
	go func() {
		select {
		case <-stopCh:
			fm.Stop()
		case <-fm.stopCh:
		}
	}()

	buf := make([]byte, 4096*24) // Large buffer for event batches
	events := make([]unix.EpollEvent, 4)

	for {
		n, err := unix.EpollWait(epfd, events, 500) // 500ms timeout
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			// Check if we've been stopped
			select {
			case <-fm.stopCh:
				fm.drainAndClose()
				return
			default:
			}
			fmt.Fprintf(os.Stderr, "[%s] epoll_wait error: %v\n", ts(), err)
			time.Sleep(1 * time.Second)
			continue
		}

		// Check for stop first
		select {
		case <-fm.stopCh:
			fm.drainAndClose()
			return
		default:
		}

		for i := 0; i < n; i++ {
			if events[i].Fd == int32(fm.pipeFds[0]) {
				// Stop signal received via pipe
				fm.drainAndClose()
				return
			}

			if events[i].Fd == int32(fm.fd) {
				// fanotify events ready
				for {
					nr, err := unix.Read(fm.fd, buf)
					if err != nil {
						if err == unix.EAGAIN || err == unix.EINTR {
							break
						}
						fmt.Fprintf(os.Stderr, "[%s] fanotify read error: %v\n", ts(), err)
						break
					}
					if nr < metadataSize {
						break
					}
					fm.processEvents(buf[:nr])
				}
			}
		}
	}
}

// runPollFallback is used when epoll setup fails; falls back to sleep-based polling.
func (fm *FileMonitor) runPollFallback(stopCh <-chan struct{}) {
	// Forward external stopCh to our internal mechanism
	go func() {
		select {
		case <-stopCh:
			fm.Stop()
		case <-fm.stopCh:
		}
	}()

	buf := make([]byte, 4096*24)

	for {
		select {
		case <-fm.stopCh:
			fm.drainAndClose()
			return
		default:
		}

		n, err := unix.Read(fm.fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			fmt.Fprintf(os.Stderr, "[%s] fanotify read error: %v\n", ts(), err)
			time.Sleep(1 * time.Second)
			continue
		}

		if n < metadataSize {
			continue
		}

		fm.processEvents(buf[:n])
	}
}

// processEvents parses a buffer of fanotify event metadata and dispatches each event.
func (fm *FileMonitor) processEvents(buf []byte) {
	offset := 0
	for offset+metadataSize <= len(buf) {
		event := (*fanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
		if event.EventLen < uint32(metadataSize) {
			break
		}

		if event.Fd >= 0 {
			fm.handleEvent(int(event.Fd))
		}

		offset += int(event.EventLen)
	}
}

// drainAndClose drains the analyzerCh and waits for workers to finish.
// C1 — ensures no fd leak on shutdown.
func (fm *FileMonitor) drainAndClose() {
	fm.drainOnce.Do(func() {
		close(fm.analyzerCh)
		fm.wg.Wait()
		// Mark pipe as closed before actually closing, so Stop() won't
		// write to an already-closed fd (H2 fix).
		atomic.StoreInt32(&fm.pipeClosed, 1)
		_ = unix.Close(fm.pipeFds[0])
		_ = unix.Close(fm.pipeFds[1])
	})
}

// Stop signals the monitor to shut down.
// C2 — sync.Once ensures safe concurrent calls; does not close analyzerCh directly.
func (fm *FileMonitor) Stop() {
	fm.stopOnce.Do(func() {
		close(fm.stopCh)
		// Wake epoll so Run() exits and calls drainAndClose.
		// Only write if pipe hasn't been closed by drainAndClose yet.
		if atomic.LoadInt32(&fm.pipeClosed) == 0 {
			_, _ = unix.Write(fm.pipeFds[1], []byte{0})
		}
		// Close fanotify fd — causes any pending Read/EpollWait to return
		_ = unix.Close(fm.fd)
	})
}

func (fm *FileMonitor) handleEvent(fd int) {
	// Get the file path from the fd via /proc/self/fd/N
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		_ = unix.Close(fd)
		return
	}

	// M5 — skip directory events
	if strings.HasSuffix(path, "/") {
		_ = unix.Close(fd)
		return
	}

	// Fast filter — decide if this file is interesting based on path only
	if !fm.isInteresting(path) {
		_ = unix.Close(fd)
		return
	}

	// Send to analyzer pool (with backpressure)
	select {
	case fm.analyzerCh <- fileEvent{path: path, fd: fd}:
	default:
		// Queue full — drop event and count
		atomic.AddInt64(&fm.droppedEvents, 1)
		_ = unix.Close(fd)
	}
}

// isInteresting is the fast filter — zero I/O, pure string matching.
func (fm *FileMonitor) isInteresting(path string) bool {
	lower := strings.ToLower(path)

	// PHP files
	if strings.HasSuffix(lower, ".php") || strings.HasSuffix(lower, ".phtml") ||
		strings.HasSuffix(lower, ".pht") || strings.HasSuffix(lower, ".php5") {
		return true
	}

	// Webshell extensions
	if strings.HasSuffix(lower, ".haxor") || strings.HasSuffix(lower, ".cgix") {
		return true
	}

	// .htaccess and .user.ini files
	if strings.HasSuffix(lower, ".htaccess") || strings.HasSuffix(lower, ".user.ini") {
		return true
	}

	// HTML files in /home (phishing pages)
	if strings.HasPrefix(path, "/home/") &&
		(strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm")) {
		return true
	}

	// Credential log files — known phishing harvest filenames
	base := filepath.Base(lower)
	if credentialLogNames[base] {
		return true
	}

	// ZIP archives in /home (phishing kit uploads)
	if strings.HasPrefix(path, "/home/") && strings.HasSuffix(lower, ".zip") {
		return true
	}

	// Anything in .config directories
	if strings.Contains(path, "/.config/") {
		return true
	}

	// Executables in /tmp or /dev/shm
	if strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/dev/shm/") {
		return true
	}

	return false
}

// credentialLogNames are filenames commonly used by phishing kits to store
// harvested credentials. Checked in isInteresting() for real-time detection.
var credentialLogNames = map[string]bool{
	"results.txt": true, "result.txt": true, "log.txt": true,
	"logs.txt": true, "emails.txt": true, "data.txt": true,
	"passwords.txt": true, "creds.txt": true, "credentials.txt": true,
	"victims.txt": true, "output.txt": true, "harvested.txt": true,
	"results.log": true, "emails.log": true, "data.log": true,
	"results.csv": true, "emails.csv": true, "data.csv": true,
}

// analyzerWorker processes file events from the bounded channel.
// C1 — on channel close, drains remaining events and closes their fds.
func (fm *FileMonitor) analyzerWorker() {
	defer fm.wg.Done()
	for event := range fm.analyzerCh {
		fm.analyzeFile(event)
		_ = unix.Close(event.fd)
	}
}

// readFromFd reads up to maxBytes from a file descriptor at position 0.
// C3 — avoids TOCTOU by reading from the original fanotify event fd.
// readFromFd reads up to maxBytes from the fanotify event fd using pread
// at offset 0. Uses unix.Pread directly to avoid os.NewFile's GC finalizer
// which would close the fd out-of-band, racing with the worker's explicit close.
func readFromFd(fd int, maxBytes int) []byte {
	buf := make([]byte, maxBytes)
	n, err := unix.Pread(fd, buf, 0)
	if n <= 0 || (err != nil && n == 0) {
		return nil
	}
	return buf[:n]
}

func (fm *FileMonitor) analyzeFile(event fileEvent) {
	path := event.path
	name := filepath.Base(path)
	nameLower := strings.ToLower(name)

	// H2 — suppression path matching using filepath.Match
	for _, ignore := range fm.cfg.Suppressions.IgnorePaths {
		if matchSuppression(ignore, path) {
			return
		}
	}

	// Immediate CRITICAL: known webshell filenames (M1 — package-level var)
	if knownWebshells[nameLower] {
		fm.sendAlertWithPath(alert.Critical, "webshell_realtime",
			fmt.Sprintf("Webshell file created: %s", path), "", path)
		return
	}

	// Webshell extensions
	if strings.HasSuffix(nameLower, ".haxor") || strings.HasSuffix(nameLower, ".cgix") {
		fm.sendAlertWithPath(alert.Critical, "webshell_realtime",
			fmt.Sprintf("Suspicious CGI file created: %s", path), "", path)
		return
	}

	// Executables in /tmp or /dev/shm — detect dropped malware/miners
	// Uses unix.Fstat on event fd for TOCTOU safety (attacker can't chmod -x after event)
	if strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/dev/shm/") {
		var tmpStat unix.Stat_t
		if err := unix.Fstat(event.fd, &tmpStat); err == nil {
			isDir := tmpStat.Mode&unix.S_IFMT == unix.S_IFDIR
			isExec := tmpStat.Mode&0111 != 0
			if !isDir && isExec {
				fm.sendAlertWithPath(alert.Critical, "executable_in_tmp_realtime",
					fmt.Sprintf("Executable created in %s: %s", filepath.Dir(path), path),
					fmt.Sprintf("Size: %d, Mode: %04o", tmpStat.Size, tmpStat.Mode&0777), path)
			}
		}
		// Fall through to PHP checks below for .php files in /tmp
		if !isPHPExtension(nameLower) {
			return
		}
	}

	// PHP in uploads directories
	if strings.Contains(path, "/wp-content/uploads/") && isPHPExtension(nameLower) {
		if nameLower != "index.php" && !isKnownSafeUploadDaemon(path) {
			if looksLikePluginUpdate(path) {
				// Verified plugin update — lower severity, don't suppress entirely
				fm.sendAlertWithPath(alert.Warning, "php_in_uploads_realtime",
					fmt.Sprintf("PHP file created in uploads (plugin update): %s", path),
					"Appears to be a legitimate plugin update temp directory", path)
			} else {
				fm.sendAlertWithPath(alert.Critical, "php_in_uploads_realtime",
					fmt.Sprintf("PHP file created in uploads: %s", path), "", path)
			}
		}
		return
	}

	// PHP in languages/upgrade directories
	if (strings.Contains(path, "/wp-content/languages/") || strings.Contains(path, "/wp-content/upgrade/")) &&
		isPHPExtension(nameLower) {
		if nameLower != "index.php" && !strings.HasSuffix(nameLower, ".l10n.php") {
			fm.sendAlertWithPath(alert.Critical, "php_in_sensitive_dir_realtime",
				fmt.Sprintf("PHP file created in sensitive WP directory: %s", path), "", path)
		}
		return
	}

	// Executables in .config
	if strings.Contains(path, "/.config/") {
		info, err := os.Stat(path)
		if err == nil && info.Mode()&0111 != 0 {
			fm.sendAlertWithPath(alert.Critical, "executable_in_config_realtime",
				fmt.Sprintf("Executable created in .config: %s", path),
				fmt.Sprintf("Size: %d", info.Size()), path)
		}
		return
	}

	// .htaccess modification — check for injection (C3 — read from fd)
	if nameLower == ".htaccess" {
		fm.checkHtaccess(event.fd, path)
		return
	}

	// .user.ini modification — check for dangerous PHP settings (C3 — read from fd)
	if nameLower == ".user.ini" {
		fm.checkUserINI(event.fd, path)
		return
	}

	// PHP content analysis (C3 — read from fd; M4 — 32KB scan size)
	if isPHPExtension(nameLower) {
		fm.checkPHPContent(event.fd, path)
		return
	}

	// HTML phishing page detection (uses event fd for content, unix.Fstat for size)
	if strings.HasSuffix(nameLower, ".html") || strings.HasSuffix(nameLower, ".htm") {
		fm.checkHTMLPhishing(event.fd, path)
		return
	}

	// Credential log files (path-based)
	if credentialLogNames[nameLower] {
		fm.checkCredentialLog(path)
		return
	}

	// Phishing kit ZIP archives (path-based)
	if strings.HasSuffix(nameLower, ".zip") {
		fm.checkPhishingZip(path, nameLower)
		return
	}
}

// checkHtaccess reads .htaccess content from the event fd and checks for injection.
// C3 — reads from fd, not path. H5 — per-line safe check.
func (fm *FileMonitor) checkHtaccess(fd int, path string) {
	data := readFromFd(fd, 16384)
	if data == nil {
		return
	}
	content := strings.ToLower(string(data))

	dangerous := []string{"auto_prepend_file", "auto_append_file", "eval(", "base64_decode"}
	safe := []string{"wordfence-waf.php", "litespeed", "advanced-headers.php", "rsssl"}

	// H5 — check each non-comment line individually
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		for _, d := range dangerous {
			if strings.Contains(line, d) {
				isSafe := false
				for _, s := range safe {
					if strings.Contains(line, s) {
						isSafe = true
						break
					}
				}
				if !isSafe {
					fm.sendAlertWithPath(alert.High, "htaccess_injection_realtime",
						fmt.Sprintf("Suspicious .htaccess modification: %s", path),
						fmt.Sprintf("Pattern: %s", d), path)
					return
				}
			}
		}
	}
}

// checkUserINI reads .user.ini content from the event fd and checks for dangerous PHP settings.
// C3 — reads from fd, not path. H6 — proper allow_url_include parsing.
func (fm *FileMonitor) checkUserINI(fd int, path string) {
	data := readFromFd(fd, 4096)
	if data == nil {
		return
	}
	content := strings.ToLower(string(data))

	dangerous := []struct {
		pattern string
		desc    string
	}{
		{"allow_url_include", "allow_url_include (remote code inclusion)"},
		{"disable_functions", "disable_functions modified"},
	}

	for _, d := range dangerous {
		if !strings.Contains(content, d.pattern) {
			continue
		}

		if d.pattern == "disable_functions" {
			for _, line := range strings.Split(content, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "disable_functions") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						val := strings.TrimSpace(parts[1])
						if val == "" || val == "\"\"" || val == "none" {
							fm.sendAlertWithPath(alert.Critical, "php_config_realtime",
								fmt.Sprintf("PHP disable_functions cleared: %s", path),
								"All dangerous PHP functions enabled — shell execution possible", path)
							return
						}
					}
				}
			}
		}

		// H6 — parse the specific line value instead of checking for "on" anywhere
		if d.pattern == "allow_url_include" {
			for _, line := range strings.Split(content, "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "allow_url_include") {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					val := strings.TrimSpace(strings.ToLower(parts[1]))
					if val == "on" || val == "1" || val == "\"on\"" || val == "'on'" {
						fm.sendAlertWithPath(alert.Critical, "php_config_realtime",
							fmt.Sprintf("PHP allow_url_include enabled: %s", path),
							"Remote PHP file inclusion is now possible", path)
						return
					}
				}
			}
		}
	}
}

// checkPHPContent reads PHP content from the event fd and checks for malicious patterns.
// C3 — reads from fd, not path. M4 — 32KB scan size.
func (fm *FileMonitor) checkPHPContent(fd int, path string) {
	data := readFromFd(fd, 32768)
	if data == nil {
		return
	}
	content := strings.ToLower(string(data))

	// Remote payload fetching
	payloads := []string{"gist.githubusercontent.com", "raw.githubusercontent.com", "pastebin.com/raw"}
	for _, p := range payloads {
		if strings.Contains(content, p) {
			fm.sendAlertWithPath(alert.Critical, "php_dropper_realtime",
				fmt.Sprintf("PHP dropper with remote payload URL: %s", path),
				fmt.Sprintf("Fetches from: %s", p), path)
			return
		}
	}

	// eval + decoder combo
	hasEval := strings.Contains(content, "eval(") || strings.Contains(content, "assert(")
	hasDecoder := strings.Contains(content, "base64_decode") || strings.Contains(content, "gzinflate") || strings.Contains(content, "gzuncompress")
	if hasEval && hasDecoder {
		fm.sendAlertWithPath(alert.Critical, "obfuscated_php_realtime",
			fmt.Sprintf("Obfuscated PHP detected: %s", path),
			"eval() combined with encoding/compression function", path)
		return
	}

	// Shell execution with request input
	shellFuncs := []string{"system(", "passthru(", "exec(", "shell_exec(", "popen("}
	requestVars := []string{"$_request", "$_post", "$_get", "$_cookie"}
	hasShell := false
	hasInput := false
	for _, sf := range shellFuncs {
		if strings.Contains(content, sf) {
			hasShell = true
		}
	}
	for _, rv := range requestVars {
		if strings.Contains(content, rv) {
			hasInput = true
		}
	}
	if hasShell && hasInput {
		fm.sendAlertWithPath(alert.Critical, "webshell_content_realtime",
			fmt.Sprintf("Webshell pattern detected: %s", path),
			"Shell execution function with request input", path)
		return
	}

	// Skip signature/YARA scanning for verified CMS core files.
	// The wp_core periodic check validates files against official checksums;
	// if a file's hash matches a known-clean core file, signature matches
	// on it are false positives (e.g. $_POST in wp-includes, mail() in
	// PHPMailer, fsockopen() in POP3.php).
	if checks.IsVerifiedCMSFile(path) {
		return
	}

	// External YAML signature scanning (if rules are loaded)
	if scanner := signatures.Global(); scanner != nil {
		matches := scanner.ScanContent(data, filepath.Ext(path))
		if len(matches) > 0 {
			m := matches[0] // one alert per file — use first match
			sev := alert.High
			if m.Severity == "critical" {
				sev = alert.Critical
			}
			fm.sendAlertWithPath(sev, "signature_match_realtime",
				fmt.Sprintf("Signature match [%s]: %s", m.RuleName, path),
				fmt.Sprintf("Category: %s\nDescription: %s\nMatched: %s",
					m.Category, m.Description, strings.Join(m.Matched, ", ")), path)
			return
		}
	}

	// YARA-X scanning (if compiled in and rules loaded)
	if yaraScanner := yara.Global(); yaraScanner != nil {
		matches := yaraScanner.ScanBytes(data)
		if len(matches) > 0 {
			fm.sendAlertWithPath(alert.Critical, "yara_match_realtime",
				fmt.Sprintf("YARA rule match [%s]: %s", matches[0].RuleName, path),
				fmt.Sprintf("Matched %d YARA rule(s)", len(matches)), path)
		}
	}
}

// checkHTMLPhishing reads an HTML file and checks for phishing indicators:
// brand impersonation + credential input + redirect/exfiltration.
// Uses event fd for content read and unix.Fstat for size (TOCTOU-safe).
func (fm *FileMonitor) checkHTMLPhishing(fd int, path string) {
	// Only check files in web-accessible directories
	if !strings.Contains(path, "/public_html/") {
		return
	}

	// Skip known safe directories
	for _, safe := range []string{"/wp-admin/", "/wp-includes/", "/wp-content/themes/",
		"/wp-content/plugins/", "/node_modules/", "/vendor/", "/.well-known/"} {
		if strings.Contains(path, safe) {
			return
		}
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return
	}
	size := stat.Size
	if size < 500 || size > 500000 {
		return
	}

	data := readFromFd(fd, 16384)
	if data == nil {
		return
	}
	content := strings.ToLower(string(data))

	// Must have a form with credential inputs
	if !strings.Contains(content, "<form") && !strings.Contains(content, "<input") {
		return
	}
	hasCredInput := strings.Contains(content, "type=\"email\"") ||
		strings.Contains(content, "type=\"password\"") ||
		strings.Contains(content, "type='email'") ||
		strings.Contains(content, "type='password'") ||
		strings.Contains(content, "name=\"email\"") ||
		strings.Contains(content, "name=\"password\"") ||
		strings.Contains(content, "placeholder=\"you@")
	if !hasCredInput {
		return
	}

	// Check for brand impersonation
	brands := []struct {
		name     string
		patterns []string
	}{
		{"Microsoft/SharePoint", []string{"sharepoint", "onedrive", "microsoft 365", "outlook web", "office 365"}},
		{"Google", []string{"google drive", "google docs", "accounts.google", "gmail"}},
		{"Dropbox", []string{"dropbox"}},
		{"DocuSign", []string{"docusign"}},
		{"Adobe", []string{"adobe sign", "adobe document"}},
		{"Apple/iCloud", []string{"icloud", "apple id"}},
		{"Webmail", []string{"roundcube", "horde", "webmail login", "zimbra"}},
		{"Generic", []string{"secure access", "verify your", "confirm your identity", "account verification"}},
	}

	brandMatch := ""
	for _, b := range brands {
		for _, p := range b.patterns {
			if strings.Contains(content, p) {
				brandMatch = b.name
				break
			}
		}
		if brandMatch != "" {
			break
		}
	}
	if brandMatch == "" {
		return
	}

	// Check for redirect/exfiltration patterns
	exfilPatterns := []string{
		"window.location.href", "window.location.replace", "window.location =",
		".workers.dev", "fetch(", "xmlhttprequest",
	}
	hasExfil := false
	for _, p := range exfilPatterns {
		if strings.Contains(content, p) {
			hasExfil = true
			break
		}
	}

	// Also check for trust badges (strong phishing signal)
	hasTrustBadge := strings.Contains(content, "secured by microsoft") ||
		strings.Contains(content, "secured by google") ||
		strings.Contains(content, "256-bit encrypted") ||
		strings.Contains(content, "256‑bit encrypted")

	if hasExfil || hasTrustBadge {
		fm.sendAlertWithPath(alert.Critical, "phishing_realtime",
			fmt.Sprintf("Phishing page created (%s impersonation): %s", brandMatch, path),
			fmt.Sprintf("Size: %d bytes", size), path)
	}
}

// checkCredentialLog reads a text file and checks if it contains harvested
// email:password pairs — output from an active phishing kit.
// Uses path-based reads because it needs path context.
func (fm *FileMonitor) checkCredentialLog(path string) {
	if !strings.Contains(path, "/public_html/") {
		return
	}

	data := readHead(path, 4096)
	if data == nil {
		return
	}
	content := string(data)
	lines := strings.Split(content, "\n")

	credLines := 0
	emailCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "@") {
			emailCount++
			for _, delim := range []string{":", "|", "\t", ","} {
				parts := strings.SplitN(line, delim, 3)
				if len(parts) >= 2 {
					p0 := strings.TrimSpace(parts[0])
					p1 := strings.TrimSpace(parts[1])
					if strings.Contains(p0, "@") && len(p1) > 0 && !strings.Contains(p1, " ") {
						credLines++
						break
					}
				}
			}
		}
	}

	if credLines >= 3 {
		fm.sendAlertWithPath(alert.Critical, "credential_log_realtime",
			fmt.Sprintf("Harvested credential log detected: %s", path),
			fmt.Sprintf("%d credential lines (email:password format) found", credLines), path)
	} else if emailCount >= 10 {
		fm.sendAlertWithPath(alert.High, "credential_log_realtime",
			fmt.Sprintf("Possible harvested email list: %s", path),
			fmt.Sprintf("%d email addresses found in %s", emailCount, filepath.Base(path)), path)
	}
}

// checkPhishingZip checks if a newly created ZIP file matches known phishing
// kit archive names.
// Uses path-based approach since it only checks the filename.
func (fm *FileMonitor) checkPhishingZip(path, nameLower string) {
	if !strings.Contains(path, "/public_html/") {
		return
	}

	kitNames := []string{
		"office365", "office 365", "sharepoint", "onedrive",
		"microsoft", "outlook", "google", "gmail",
		"dropbox", "docusign", "adobe", "wetransfer",
		"paypal", "apple", "icloud", "netflix",
		"facebook", "instagram", "linkedin",
		"login", "phish", "scam", "kit",
		"webmail", "roundcube", "cpanel",
		"bank", "verify", "secure",
	}

	for _, kit := range kitNames {
		if strings.Contains(nameLower, kit) {
			fm.sendAlertWithPath(alert.High, "phishing_kit_realtime",
				fmt.Sprintf("Suspected phishing kit archive uploaded: %s", path),
				fmt.Sprintf("Filename matches phishing kit pattern: '%s'", kit), path)
			return
		}
	}
}

// M7 — sendAlert uses droppedAlerts counter, separate from droppedEvents.
func (fm *FileMonitor) sendAlert(severity alert.Severity, check, message, details string) {
	finding := alert.Finding{
		Severity:  severity,
		Check:     check,
		Message:   message,
		Details:   details,
		Timestamp: time.Now(),
	}
	select {
	case fm.alertCh <- finding:
	default:
		atomic.AddInt64(&fm.droppedAlerts, 1)
	}
}

// sendAlertWithPath is like sendAlert but also sets the FilePath field
// for structured file-path propagation to auto-response.
func (fm *FileMonitor) sendAlertWithPath(severity alert.Severity, check, message, details, filePath string) {
	finding := alert.Finding{
		Severity:  severity,
		Check:     check,
		Message:   message,
		Details:   details,
		FilePath:  filePath,
		Timestamp: time.Now(),
	}
	select {
	case fm.alertCh <- finding:
	default:
		atomic.AddInt64(&fm.droppedAlerts, 1)
	}
}

// M7 — overflowReporter reports dropped events and alerts separately.
func (fm *FileMonitor) overflowReporter() {
	defer fm.wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-fm.stopCh:
			return
		case <-ticker.C:
			droppedEv := atomic.SwapInt64(&fm.droppedEvents, 0)
			droppedAl := atomic.SwapInt64(&fm.droppedAlerts, 0)
			if droppedEv > 0 {
				fm.sendAlert(alert.Warning, "fanotify_overflow",
					fmt.Sprintf("fanotify event queue overflowed: %d events dropped in last minute", droppedEv),
					"Possible event storm (backup, bulk update) or high-volume attack")
			}
			if droppedAl > 0 {
				fmt.Fprintf(os.Stderr, "[%s] alert channel full: %d alerts dropped in last minute\n", ts(), droppedAl)
			}
		}
	}
}

// isPHPExtension returns true for all PHP file extensions that can execute code.
func isPHPExtension(nameLower string) bool {
	return strings.HasSuffix(nameLower, ".php") ||
		strings.HasSuffix(nameLower, ".phtml") ||
		strings.HasSuffix(nameLower, ".pht") ||
		strings.HasSuffix(nameLower, ".php5")
}

// matchSuppression checks if a file path matches a suppression glob pattern.
// Supports patterns like "*/cache/*", "*/vendor/*", "*.log".
// Uses filepath.Match per path segment for wildcard patterns.
func matchSuppression(pattern, path string) bool {
	// Direct match against full path
	if m, _ := filepath.Match(pattern, path); m {
		return true
	}
	// Match against basename (e.g. "*.log")
	if m, _ := filepath.Match(pattern, filepath.Base(path)); m {
		return true
	}
	// For patterns like "*/cache/*": check if any directory segment matches
	// the non-wildcard core of the pattern. We split the pattern on "/" and
	// match each pattern segment against the corresponding path segments.
	patParts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, "/")
	if len(patParts) < 2 {
		return false
	}
	// Sliding window: try to align pattern segments with path segments.
	// Empty pattern parts (from leading/trailing/double slashes) match any segment.
	for i := 0; i <= len(pathParts)-len(patParts); i++ {
		allMatch := true
		for j, pp := range patParts {
			if pp == "" {
				continue // empty segment matches anything (acts as wildcard)
			}
			if i+j >= len(pathParts) {
				allMatch = false
				break
			}
			m, _ := filepath.Match(pp, pathParts[i+j])
			if !m {
				allMatch = false
				break
			}
		}
		// Only count as match if we consumed at least one non-empty pattern part
		if allMatch {
			hasNonEmpty := false
			for _, pp := range patParts {
				if pp != "" {
					hasNonEmpty = true
					break
				}
			}
			if hasNonEmpty {
				return true
			}
		}
	}
	return false
}

// readHead opens a file by path and reads the first maxBytes.
// Kept for path-based checks (HTML phishing, credential logs, ZIP checks)
// that need os.Stat for file size anyway.
func readHead(path string, maxBytes int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, maxBytes)
	n, _ := f.Read(buf)
	if n == 0 {
		return nil
	}
	return buf[:n]
}

func isKnownSafeUploadDaemon(path string) bool {
	safePaths := []string{
		"/cache/", "/imunify", "/redux/", "/mailchimp-for-wp/",
		"/sucuri/", "/smush/", "/goldish/", "/wpallexport/",
		"/wpallimport/", "/wph/", "/stm_fonts/", "/smile_fonts/",
		"/bws-custom-code/", "/wp-import-export-lite/",
		"/zn_fonts/", "/companies_documents/",
	}
	for _, sp := range safePaths {
		if strings.Contains(path, sp) {
			return true
		}
	}

	return false
}

// looksLikePluginUpdate checks if a PHP file in uploads looks like a plugin
// update temp directory (e.g., elementor_t0q9y). Returns true if it matches
// the pattern of a known plugin extracting an update.
// M3 — uses sync.Map cache with 5-minute TTL for plugin directory stat results.
func looksLikePluginUpdate(path string) bool {
	// WordPress plugin updates extract to /uploads/{pluginname}_{random}/
	// Detect by extracting the directory name under uploads/ and checking
	// if a matching plugin exists in wp-content/plugins/.
	// No hardcoded whitelist — works for all 60,000+ WP plugins.
	uploadsIdx := strings.Index(path, "/wp-content/uploads/")
	if uploadsIdx < 0 {
		return false
	}
	wpRoot := path[:uploadsIdx]
	afterUploads := path[uploadsIdx+len("/wp-content/uploads/"):]

	// Extract the first directory component: "header-footer_7ocsd"
	slashIdx := strings.Index(afterUploads, "/")
	if slashIdx < 0 {
		return false
	}
	dirName := afterUploads[:slashIdx]

	// Strip the random suffix (e.g. "_7ocsd") — WordPress appends _XXXXX
	// The plugin name is everything before the last underscore-followed-by-random
	pluginName := dirName
	if lastUnderscore := strings.LastIndex(dirName, "_"); lastUnderscore > 0 {
		suffix := dirName[lastUnderscore+1:]
		// Random suffixes are short alphanumeric strings (5-8 chars)
		if len(suffix) >= 4 && len(suffix) <= 10 {
			pluginName = dirName[:lastUnderscore]
		}
	}

	// Check if a matching plugin directory exists in plugins/
	pluginDir := wpRoot + "/wp-content/plugins/" + pluginName

	// M3 — check cache first
	if cached, ok := pluginStatCache.Load(pluginDir); ok {
		entry := cached.(pluginCacheEntry)
		if time.Since(entry.ts) < pluginCacheTTL {
			return entry.exists
		}
	}

	_, err := os.Stat(pluginDir)
	exists := err == nil
	pluginStatCache.Store(pluginDir, pluginCacheEntry{
		exists: exists,
		ts:     time.Now(),
	})
	return exists
}
