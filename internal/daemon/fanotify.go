//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
)

const (
	sysFanotifyInit = 300
	sysFanotifyMark = 301
)

// fanotify constants (not all in Go stdlib)
const (
	FAN_MARK_ADD                  = 0x00000001
	FAN_MARK_MOUNT                = 0x00000010
	FAN_CLOSE_WRITE               = 0x00000008
	FAN_CREATE                    = 0x00000100
	FAN_ONDIR                     = 0x40000000
	FAN_EVENT_ON_CHILD            = 0x08000000
	FAN_CLASS_NOTIF               = 0x00000000
	FAN_CLOEXEC                   = 0x00000001
	FAN_NONBLOCK                  = 0x00000002
	FAN_REPORT_FID                = 0x00000200
	FAN_REPORT_DFID_NAME          = 0x00000C00
	FAN_EVENT_INFO_TYPE_DFID_NAME = 2
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

// FileMonitor watches mount points for file creation/modification using fanotify.
type FileMonitor struct {
	fd         int
	cfg        *config.Config
	alertCh    chan<- alert.Finding
	dropped    int64 // atomic counter for dropped events
	analyzerCh chan fileEvent
}

type fileEvent struct {
	path string
	fd   int
}

// NewFileMonitor creates a fanotify-based file monitor.
// Returns error if the kernel doesn't support the required features.
func NewFileMonitor(cfg *config.Config, alertCh chan<- alert.Finding) (*FileMonitor, error) {
	// Try FAN_REPORT_DFID_NAME first (Linux 5.9+), then FAN_REPORT_FID (5.1+), then basic
	var fd int
	var err error

	// Basic fanotify without filename reporting — we'll use /proc/self/fd/N readlink
	fd, err = fanotifyInit(FAN_CLASS_NOTIF|FAN_CLOEXEC|FAN_NONBLOCK, syscall.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w (kernel may not support fanotify)", err)
	}

	// Mark mount points
	mountPaths := []string{"/home", "/tmp", "/dev/shm"}
	for _, path := range mountPaths {
		err = fanotifyMark(fd, FAN_MARK_ADD|FAN_MARK_MOUNT, FAN_CLOSE_WRITE|FAN_CREATE, -1, path)
		if err != nil {
			// Try without FAN_CREATE (older kernels)
			err = fanotifyMark(fd, FAN_MARK_ADD|FAN_MARK_MOUNT, FAN_CLOSE_WRITE, -1, path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s] Warning: cannot watch %s: %v\n", ts(), path, err)
			}
		}
	}

	fm := &FileMonitor{
		fd:         fd,
		cfg:        cfg,
		alertCh:    alertCh,
		analyzerCh: make(chan fileEvent, 1000), // bounded queue
	}

	return fm, nil
}

// Run starts the file monitor event loop and analyzer workers.
func (fm *FileMonitor) Run(stopCh <-chan struct{}) {
	// Start analyzer workers
	for i := 0; i < 3; i++ {
		go fm.analyzerWorker(stopCh)
	}

	// Start overflow reporter
	go fm.overflowReporter(stopCh)

	buf := make([]byte, 4096*24) // Large buffer for event batches

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		n, err := syscall.Read(fm.fd, buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				// No events ready — sleep briefly to avoid busy loop
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

		// Process events
		offset := 0
		for offset+metadataSize <= n {
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
}

// Stop closes the fanotify fd.
func (fm *FileMonitor) Stop() {
	_ = syscall.Close(fm.fd)
	close(fm.analyzerCh)
}

func (fm *FileMonitor) handleEvent(fd int) {
	// Get the file path from the fd via /proc/self/fd/N
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		_ = syscall.Close(fd)
		return
	}

	// Fast filter — decide if this file is interesting based on path only
	if !fm.isInteresting(path) {
		_ = syscall.Close(fd)
		return
	}

	// Send to analyzer pool (with backpressure)
	select {
	case fm.analyzerCh <- fileEvent{path: path, fd: fd}:
	default:
		// Queue full — drop event and count
		atomic.AddInt64(&fm.dropped, 1)
		_ = syscall.Close(fd)
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

	// .htaccess files
	if strings.HasSuffix(lower, ".htaccess") {
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

// analyzerWorker processes file events from the bounded channel.
func (fm *FileMonitor) analyzerWorker(stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		case event, ok := <-fm.analyzerCh:
			if !ok {
				return
			}
			fm.analyzeFile(event)
			_ = syscall.Close(event.fd)
		}
	}
}

func (fm *FileMonitor) analyzeFile(event fileEvent) {
	path := event.path
	name := filepath.Base(path)
	nameLower := strings.ToLower(name)

	// Skip suppressed paths
	for _, ignore := range fm.cfg.Suppressions.IgnorePaths {
		if strings.Contains(path, strings.ReplaceAll(ignore, "*", "")) {
			return
		}
	}

	// Immediate CRITICAL: known webshell filenames
	webshells := map[string]bool{
		"h4x0r.php": true, "c99.php": true, "r57.php": true,
		"wso.php": true, "alfa.php": true, "b374k.php": true,
		"shell.php": true, "cmd.php": true, "backdoor.php": true,
		"webshell.php": true,
	}
	if webshells[nameLower] {
		fm.sendAlert(alert.Critical, "webshell_realtime",
			fmt.Sprintf("Webshell file created: %s", path), "")
		return
	}

	// Webshell extensions
	if strings.HasSuffix(nameLower, ".haxor") || strings.HasSuffix(nameLower, ".cgix") {
		fm.sendAlert(alert.Critical, "webshell_realtime",
			fmt.Sprintf("Suspicious CGI file created: %s", path), "")
		return
	}

	// PHP in uploads directories
	if strings.Contains(path, "/wp-content/uploads/") && strings.HasSuffix(nameLower, ".php") {
		if nameLower != "index.php" && !isKnownSafeUploadDaemon(path) {
			fm.sendAlert(alert.Critical, "php_in_uploads_realtime",
				fmt.Sprintf("PHP file created in uploads: %s", path), "")
		}
		return
	}

	// PHP in languages/upgrade directories
	if (strings.Contains(path, "/wp-content/languages/") || strings.Contains(path, "/wp-content/upgrade/")) &&
		strings.HasSuffix(nameLower, ".php") {
		if nameLower != "index.php" && !strings.HasSuffix(nameLower, ".l10n.php") {
			fm.sendAlert(alert.Critical, "php_in_sensitive_dir_realtime",
				fmt.Sprintf("PHP file created in sensitive WP directory: %s", path), "")
		}
		return
	}

	// Executables in .config
	if strings.Contains(path, "/.config/") {
		info, err := os.Stat(path)
		if err == nil && info.Mode()&0111 != 0 {
			fm.sendAlert(alert.Critical, "executable_in_config_realtime",
				fmt.Sprintf("Executable created in .config: %s", path),
				fmt.Sprintf("Size: %d", info.Size()))
		}
		return
	}

	// .htaccess modification — check for injection
	if nameLower == ".htaccess" {
		fm.checkHtaccess(path)
		return
	}

	// PHP content analysis — read first 8KB
	if strings.HasSuffix(nameLower, ".php") {
		fm.checkPHPContent(path)
	}
}

func (fm *FileMonitor) checkHtaccess(path string) {
	data := readHead(path, 4096)
	if data == nil {
		return
	}
	content := strings.ToLower(string(data))

	dangerous := []string{"auto_prepend_file", "auto_append_file", "eval(", "base64_decode"}
	safe := []string{"wordfence-waf.php", "litespeed", "advanced-headers.php", "rsssl"}

	for _, d := range dangerous {
		if strings.Contains(content, d) {
			isSafe := false
			for _, s := range safe {
				if strings.Contains(content, s) {
					isSafe = true
					break
				}
			}
			if !isSafe {
				fm.sendAlert(alert.High, "htaccess_injection_realtime",
					fmt.Sprintf("Suspicious .htaccess modification: %s", path),
					fmt.Sprintf("Pattern: %s", d))
				return
			}
		}
	}
}

func (fm *FileMonitor) checkPHPContent(path string) {
	data := readHead(path, 8192)
	if data == nil {
		return
	}
	content := strings.ToLower(string(data))

	// Remote payload fetching
	payloads := []string{"gist.githubusercontent.com", "raw.githubusercontent.com", "pastebin.com/raw"}
	for _, p := range payloads {
		if strings.Contains(content, p) {
			fm.sendAlert(alert.Critical, "php_dropper_realtime",
				fmt.Sprintf("PHP dropper with remote payload URL: %s", path),
				fmt.Sprintf("Fetches from: %s", p))
			return
		}
	}

	// eval + decoder combo
	hasEval := strings.Contains(content, "eval(") || strings.Contains(content, "assert(")
	hasDecoder := strings.Contains(content, "base64_decode") || strings.Contains(content, "gzinflate") || strings.Contains(content, "gzuncompress")
	if hasEval && hasDecoder {
		fm.sendAlert(alert.Critical, "obfuscated_php_realtime",
			fmt.Sprintf("Obfuscated PHP detected: %s", path),
			"eval() combined with encoding/compression function")
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
		fm.sendAlert(alert.Critical, "webshell_content_realtime",
			fmt.Sprintf("Webshell pattern detected: %s", path),
			"Shell execution function with request input")
	}
}

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
		atomic.AddInt64(&fm.dropped, 1)
	}
}

// overflowReporter periodically checks for dropped events.
func (fm *FileMonitor) overflowReporter(stopCh <-chan struct{}) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			dropped := atomic.SwapInt64(&fm.dropped, 0)
			if dropped > 0 {
				fm.sendAlert(alert.Warning, "fanotify_overflow",
					fmt.Sprintf("fanotify event queue overflowed: %d events dropped in last minute", dropped),
					"Possible event storm (backup, bulk update) or high-volume attack")
			}
		}
	}
}

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

// --- syscall wrappers ---

func fanotifyInit(flags, eventFlags uint) (int, error) {
	fd, _, errno := syscall.Syscall(uintptr(sysFanotifyInit), uintptr(flags), uintptr(eventFlags), 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func fanotifyMark(fd int, flags, mask uint64, dirfd int, path string) error {
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		uintptr(sysFanotifyMark),
		uintptr(fd),
		uintptr(flags),
		uintptr(mask),
		uintptr(dirfd),
		uintptr(unsafe.Pointer(pathBytes)),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
