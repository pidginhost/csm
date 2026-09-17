//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/contenttype"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/wpcheck"
	"github.com/pidginhost/csm/internal/yara"
)

// fanotify constants (not all in Go stdlib)
const (
	FAN_MARK_ADD = 0x00000001
	// FAN_MARK_MOUNT covers a single vfsmount. FAN_MARK_FILESYSTEM marks the
	// whole superblock, so a write that reaches the same inode through a bind
	// mount is reported too. EL8 backported the flag into 4.18, which is what
	// CloudLinux 8 runs, so cages are reachable on production kernels.
	FAN_MARK_MOUNT      = 0x00000010
	FAN_MARK_FILESYSTEM = 0x00000100
	FAN_CLOSE_WRITE     = 0x00000008
	FAN_CREATE          = 0x00000100
	FAN_CLASS_NOTIF     = 0x00000000
	FAN_CLOEXEC         = 0x00000001
	FAN_NONBLOCK        = 0x00000002
)

// markFunc is the fanotify_mark syscall, passed in so the ladder can be
// exercised without a kernel and without a mutable package-level seam that
// concurrent tests would race on.
type markFunc func(fd int, flags uint, mask uint64, dirFd int, path string) error

// markScope records how widely a watch root ended up being marked.
type markScope int

const (
	markScopeNone markScope = iota
	markScopeFilesystem
	markScopeMount
)

func (s markScope) String() string {
	switch s {
	case markScopeFilesystem:
		return "filesystem"
	case markScopeMount:
		return "mount"
	default:
		return "none"
	}
}

// markWatchRoot watches path, preferring a filesystem-scoped mark.
//
// A mount-scoped mark sees only the vfsmount it was added to. Every CloudLinux
// CageFS account reaches its files through a bind mount of the same superblock,
// so writes inside a cage produced no event at all and the realtime scanner was
// blind for precisely the accounts most likely to be compromised. Marking the
// superblock covers every mount of it.
//
// The ladder degrades in two independent directions: kernels without
// FAN_MARK_FILESYSTEM fall back to the mount mark, and kernels without
// FAN_CREATE (EL8 among them) keep their scope and drop that event bit.
func markWatchRoot(fd int, path string, mark markFunc) (markScope, error) {
	var lastErr error
	for _, attempt := range []struct {
		scope markScope
		flags uint
	}{
		{markScopeFilesystem, FAN_MARK_ADD | FAN_MARK_FILESYSTEM},
		{markScopeMount, FAN_MARK_ADD | FAN_MARK_MOUNT},
	} {
		for _, mask := range []uint64{FAN_CLOSE_WRITE | FAN_CREATE, FAN_CLOSE_WRITE} {
			if err := mark(fd, attempt.flags, mask, -1, path); err != nil {
				lastErr = err
				continue
			}
			return attempt.scope, nil
		}
	}
	return markScopeNone, lastErr
}

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

const htaccessRealtimeMaxBytes = 1 << 20

// M1 - webshells map at package level (avoid per-call allocation)
var knownWebshells = map[string]bool{
	"h4x0r.php": true, "c99.php": true, "r57.php": true,
	"wso.php": true, "alfa.php": true, "b374k.php": true,
	"shell.php": true, "cmd.php": true, "backdoor.php": true,
	"webshell.php": true,
}

// M3 - WordPress path stat cache with TTL
type wpPathCacheEntry struct {
	exists bool
	ts     time.Time
}

var wpPathStatCache sync.Map // key: path string → value: wpPathCacheEntry

const wpPathCacheTTL = 5 * time.Minute

// alertDedupTTL is the cooldown period for duplicate alerts on the same
// check+filepath combination. Prevents alert storms from rapid writes.
const alertDedupTTL = 30 * time.Second

// FileMonitor watches mount points for file creation/modification using fanotify.
type FileMonitor struct {
	fd      int
	cfg     *config.Config
	alertCh chan<- alert.Finding

	// panicMu / lastPanicAt rate-limit the realtime_scanner_panic finding
	// raised when an analyzer panics on one event (see analyzeFileSafe).
	panicMu           sync.Mutex
	lastPanicAt       time.Time
	analyzerCh        chan fileEvent
	queueHealthOnce   sync.Once
	analyzerHealth    *queuehealth.Tracker
	reconcileHealth   *queuehealth.Tracker
	kernelQueueHealth *queuehealth.Tracker
	kernelQueue       *notificationQueue

	// M7 - separate counters for dropped events and alerts
	droppedEvents int64
	droppedAlerts int64

	// queueOverflows counts FAN_Q_OVERFLOW events: the kernel notification
	// queue filled and events were dropped before userspace ever saw them.
	// Distinct from droppedEvents (analyzer-queue backpressure in userspace)
	// because a kernel overflow carries no fd, so the affected files are
	// unknown and cannot be reconciled by path.
	queueOverflows int64

	// overflowReportMu rate-limits the operator-facing kernel-overflow finding
	// so a sustained storm does not flood the alert channel.
	overflowReportMu   sync.Mutex
	lastOverflowReport time.Time
	yaraErrorReportMu  sync.Mutex
	lastYARAError      time.Time

	// C4 - pipe for epoll stop signaling
	pipeFds    [2]int // [0]=read, [1]=write
	pipeClosed int32  // atomic flag: 1 = pipe fds closed by drainAndClose

	// C2 - sync.Once for safe Stop
	stopOnce  sync.Once
	drainOnce sync.Once
	stopCh    chan struct{} // internal stop channel
	wg        sync.WaitGroup

	// Per-path alert deduplication: "check:filepath" → last alert time
	alertDedup sync.Map

	// accountRootPatterns and docRootPatterns describe where accounts and their
	// document roots live on this platform. The realtime detectors used to
	// hardcode /home and /public_html, which made every one of them dead on
	// Plesk and DirectAdmin and on cPanel accounts outside /home.
	accountRootPatterns []string
	docRootPatterns     []string
	// webRootPatterns is the immutable PHP configuration root set captured at
	// startup from account_roots and platform discovery.
	webRootPatterns []string

	// WordPress checksum verifier: skips detection on unmodified core and
	// plugin files and judges staged update packages file by file.
	wpCache wpVerifier
	// wpPending holds staged package files whose checksums are still being
	// fetched; stagedPackageLoop resolves them once a second.
	wpPending     *stagedPackageQueue
	wpPendingInit sync.Once

	// Drop-recovery reconcile: directories that had fanotify events dropped
	// because the analyzer queue was full. The overflow reporter walks this
	// set once a minute and scans any interesting file modified within
	// reconcileWindow so bulk filesystem operations (unzip, backup restore)
	// do not blind detection to actual threats landing in the storm.
	reconcileMu   sync.Mutex
	reconcileDirs map[string]reconcileDirectory

	// reconcileSig is a buffered cap-1 channel that lets sendEvent's drop
	// branch nudge overflowReporter to run reconcileDrops out of cycle
	// when sustained drops cross eagerReconcileDropThreshold. The cap-1
	// shape collapses multiple triggers in the same window into one and
	// keeps sendEvent non-blocking on the event-loop hot path.
	reconcileSig chan struct{}

	// metricsOnce guards one-time registration of the fanotify-scoped
	// Prometheus metrics. Each FileMonitor registers its own hooks when
	// it first starts; subsequent calls are a no-op.
	metricsOnce sync.Once

	// dropper drives the self-deleting-dropper detector: candidates are
	// admitted from the analyzer path and probed for deletion after a TTL by
	// dropperProbeLoop. nil when thresholds.dropper_detection is off.
	dropper *dropperEngine
	// dropperDocroots is the cached web-document-root list the admission
	// gate matches paths against, refreshed on the probe loop's cadence so
	// account add/remove is picked up without a restart.
	dropperDocroots atomic.Value // []string
	// dropperQuarantines records exact snapshots of files CSM moved out of
	// their original paths, so the later absence probe does not misclassify
	// CSM's own remediation as attacker self-deletion.
	dropperQuarantines *dropperQuarantineLedger
	// dropperOverflowReported is the last cumulative tracker-overflow count
	// surfaced to the operator. Only the probe goroutine accesses it.
	dropperOverflowReported   uint64
	lastDropperOverflowReport time.Time
	// dropperHandlerCache shares immutable inherited .htaccess PHP mappings
	// across analyzer events. The generation changes as soon as a .htaccess
	// event reaches the reader, invalidating every inherited snapshot.
	dropperHandlerMu         sync.Mutex
	dropperHandlerCache      map[string]dropperPHPHandlerCacheEntry
	dropperHandlerGeneration uint64
}

const (
	// reconcileDirCap bounds the dirty-region tracker fed by sendEvent's
	// drop branch. A 2026-04-28 cpanel package restore overflowed the
	// previous 64-entry cap inside seconds (every wp-content subdir was
	// a distinct parent), evicting older dirs before reconcileDrops ran.
	// 1024 entries fits typical cpanel restore bursts comfortably while
	// staying tiny in memory (each entry is a string-pointer + time, so
	// the whole map peaks under ~100 KiB even at full cap).
	reconcileDirCap = 1024

	// reconcileWindow scopes which files reconcileDrops will rescan: only
	// files whose mtime is within this window of "now". Sized just over
	// the minute tick so a drop near the start of a tick is still picked
	// up by the reconcile that runs at tick end.
	reconcileWindow = 70 * time.Second

	// analyzerChBufferSize sizes the channel feeding the analyzer pool.
	// A cpanel package restore in production observed ~4189 events in a
	// few seconds; a 16 KiB buffer absorbs that burst plus headroom
	// without ever overflowing. Memory cost is bounded (fileEvent is a
	// path string + fd + pid, ~40 bytes each, so <1 MiB at full buffer).
	analyzerChBufferSize = 16384

	// eagerReconcileDropThreshold triggers an out-of-cycle reconcile
	// when sustained drops cross this count within a single minute tick.
	// Without this, drops happening just after a tick wait the full
	// interval before reconcileDrops walks them - long enough for the
	// reconcileWindow to expire on the earliest dropped files.
	eagerReconcileDropThreshold = 500
)

// Package-level Prometheus metrics for fanotify. Instantiated once per
// process; one FileMonitor per daemon instance reuses them.
var (
	fanotifyDroppedTotal        *metrics.Counter
	fanotifyKernelOverflowTotal *metrics.Counter
	fanotifyReconcileDur        *metrics.Histogram
	contentScanTruncated        *metrics.CounterVec
)

// registerFanotifyMetrics is called once per FileMonitor via
// fm.metricsOnce. Safe to call multiple times at the FileMonitor
// layer; the package-level sync.Once guards the actual registrations.
var fanotifyMetricsInit sync.Once

func (fm *FileMonitor) registerMetrics() {
	fm.metricsOnce.Do(func() {
		fanotifyMetricsInit.Do(func() {
			fanotifyDroppedTotal = metrics.NewCounter(
				"csm_fanotify_events_dropped_total",
				"Fanotify events dropped because the analyzer queue was full. Sustained growth indicates an event storm (bulk unzip, backup restore) or an attack producing more file activity than the scanner can analyse; the reconcile pass still rescans affected directories, so dropped events do not vanish from detection, they arrive delayed.",
			)
			metrics.MustRegister("csm_fanotify_events_dropped_total", fanotifyDroppedTotal)

			fanotifyKernelOverflowTotal = metrics.NewCounter(
				"csm_fanotify_kernel_queue_overflow_total",
				"FAN_Q_OVERFLOW events: the kernel fanotify notification queue filled and dropped events before userspace read them. Unlike analyzer-queue drops these carry no fd, so the affected files are unknown; the next scheduled deep scan is the backstop. Sustained growth means a storm (bulk unzip, backup restore) or an attack producing more file activity than the reader can drain.",
			)
			metrics.MustRegister("csm_fanotify_kernel_queue_overflow_total", fanotifyKernelOverflowTotal)

			fanotifyReconcileDur = metrics.NewHistogram(
				"csm_fanotify_reconcile_latency_seconds",
				"How long the post-overflow reconcile pass takes to walk drop-affected directories and rescan recent files. Buckets sized for the observed range; alert if p99 crosses tens of seconds (reconcile is stealing CPU from real-time analysis).",
				[]float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60},
			)
			metrics.MustRegister("csm_fanotify_reconcile_latency_seconds", fanotifyReconcileDur)

			metrics.RegisterGaugeFunc(
				"csm_fanotify_queue_depth",
				"Current number of queued fanotify events waiting for the analyzer pool. Capacity is 4000; queue approaching that cap means drops are imminent.",
				func() float64 {
					if fm == nil || fm.analyzerCh == nil {
						return 0
					}
					return float64(len(fm.analyzerCh))
				},
			)

			contentScanTruncated = metrics.NewCounterVec(
				"csm_realtime_content_scan_truncated_total",
				"Real-time fanotify content checks whose file was larger than the main read window, so the full-rule pass saw only the leading window. Labels: check (phpcontent_inline, phpcontent_uploads, php_check, crontab, htaccess, user_ini, html_phishing, cgi_backdoor).",
				[]string{"check"},
			)
			metrics.MustRegister("csm_realtime_content_scan_truncated_total", contentScanTruncated)
		})
	})
}

// recordReadTruncation increments csm_realtime_content_scan_truncated_total
// when the file behind fd is larger than maxBytes. Cheap fstat per scan.
// No-op if the counter has not been registered (test setups that skip
// registerMetrics).
func recordReadTruncation(fd int, maxBytes int, check string) {
	if contentScanTruncated == nil {
		return
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return
	}
	if st.Size > int64(maxBytes) {
		contentScanTruncated.With(check).Inc()
	}
}

type fileEvent struct {
	queueTicket   queuehealth.Ticket
	path          string
	fd            int
	pid           int32
	mask          uint64
	dropperOnly   bool
	phpExecutable bool
}

func (fm *FileMonitor) currentCfg() *config.Config {
	if cfg := config.Active(); cfg != nil {
		return cfg
	}
	if fm == nil {
		return nil
	}
	return fm.cfg
}

// NewFileMonitor creates a fanotify-based file monitor.
// Returns error if the kernel doesn't support the required features.
func NewFileMonitor(cfg *config.Config, alertCh chan<- alert.Finding) (*FileMonitor, error) {
	// H1 - use golang.org/x/sys/unix for fanotify_init
	fd, err := unix.FanotifyInit(FAN_CLASS_NOTIF|FAN_CLOEXEC|FAN_NONBLOCK, unix.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w (kernel may not support fanotify)", err)
	}

	// Mark mount points; M2 - track successful mounts
	webRootPatterns := checks.PHPConfigRealtimeRootPatterns(cfg)
	mountPaths := fanotifyMountPaths(webRootPatterns)
	mountOK := 0
	var mountScoped []string
	for index, path := range mountPaths {
		if index >= 4 {
			if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
				continue
			} else if statErr != nil {
				fmt.Fprintf(os.Stderr, "[%s] Warning: cannot inspect configured watch root %s: %v\n", ts(), path, statErr)
				continue
			}
		}
		scope, markErr := markWatchRoot(fd, path, unix.FanotifyMark)
		if markErr != nil {
			fmt.Fprintf(os.Stderr, "[%s] Warning: cannot watch %s: %v\n", ts(), path, markErr)
			continue
		}
		if scope == markScopeMount {
			mountScoped = append(mountScoped, path)
		}
		mountOK++
	}
	if len(mountScoped) > 0 {
		// Worth saying out loud: on these roots a write that arrives through a
		// bind mount (a CageFS cage) raises no event, and only the rolling
		// content scan will meet it.
		fmt.Fprintf(os.Stderr, "[%s] Warning: watching %v per-mount only; writes through bind mounts on them are not seen in real time\n",
			ts(), mountScoped)
	}

	// M2 - error on zero successful mounts
	if mountOK == 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("no mount points could be watched (tried %v)", mountPaths)
	}

	// Directory-scoped watch on /var/spool/cron so any user crontab write
	// reaches analyzeFile in real time. Best-effort: cron may live under a
	// different path on non-cPanel hosts (the platform layer normalises),
	// and we'd rather lose the realtime crontab signal than fail daemon
	// startup. The polled CheckCrontabs run still covers this case via
	// the next scheduled scan. Mask matches spoolwatch.go (the proven
	// production pattern for directory-scoped marks): FAN_CLOSE_WRITE
	// alone catches both new and modified crontabs, since the close
	// after O_CREAT|O_WRONLY|... fires the close-write event. FAN_CREATE
	// is omitted because it has stricter kernel requirements with
	// directory-scoped (non-MOUNT) marks and adds no coverage here.
	if _, statErr := os.Stat(cronSpoolDir()); statErr == nil {
		if err := unix.FanotifyMark(fd, FAN_MARK_ADD,
			FAN_CLOSE_WRITE|FAN_EVENT_ON_CHILD, -1, cronSpoolDir()); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] Warning: cannot watch %s: %v\n", ts(), cronSpoolDir(), err)
		}
	}

	// C4 - create pipe for epoll stop signaling
	var pipeFds [2]int
	if err := unix.Pipe2(pipeFds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("pipe2: %w", err)
	}

	fm := &FileMonitor{
		fd:                  fd,
		cfg:                 cfg,
		alertCh:             alertCh,
		analyzerCh:          make(chan fileEvent, analyzerChBufferSize),
		pipeFds:             pipeFds,
		stopCh:              make(chan struct{}),
		reconcileDirs:       make(map[string]reconcileDirectory),
		reconcileSig:        make(chan struct{}, 1),
		webRootPatterns:     webRootPatterns,
		accountRootPatterns: checks.AccountHomePatterns(),
		docRootPatterns:     checks.RealtimeDocumentRootPatterns(cfg),
	}

	wpCache := wpcheck.NewCache(cfg.StatePath)
	wpCache.SetStopCh(fm.stopCh)
	fm.wpCache = wpCache
	fm.wpPending = newStagedPackageQueue(stagedPackageQueueMax)

	fm.initDropperDetector(cfg)

	return fm, nil
}

func fanotifyMountPaths(webRootPatterns []string) []string {
	paths := []string{"/home", "/tmp", "/dev/shm", "/var/tmp"}
	seen := make(map[string]struct{}, len(paths)+len(webRootPatterns))
	for _, path := range paths {
		seen[path] = struct{}{}
	}
	for _, pattern := range webRootPatterns {
		anchor := fanotifyMountAnchor(pattern)
		if anchor == "" {
			continue
		}
		if _, exists := seen[anchor]; exists {
			continue
		}
		seen[anchor] = struct{}{}
		paths = append(paths, anchor)
	}
	return paths
}

func fanotifyMountAnchor(pattern string) string {
	if strings.TrimSpace(pattern) == "" {
		return ""
	}
	clean := filepath.Clean(pattern)
	if !filepath.IsAbs(clean) {
		return ""
	}
	meta := strings.IndexAny(clean, "*?[")
	if meta < 0 {
		return clean
	}
	prefix := clean[:meta]
	if strings.HasSuffix(prefix, string(filepath.Separator)) {
		return filepath.Clean(prefix)
	}
	return filepath.Dir(prefix)
}

// Run starts the file monitor event loop and analyzer workers.
func (fm *FileMonitor) Run(stopCh <-chan struct{}) {
	// H7 - configurable workers: min 4, max 16, based on NumCPU
	numWorkers := runtime.NumCPU()
	if numWorkers < 4 {
		numWorkers = 4
	}
	if numWorkers > 16 {
		numWorkers = 16
	}

	for i := 0; i < numWorkers; i++ {
		fm.wg.Add(1)
		obs.Go("fanotify-analyzer", fm.analyzerWorker)
	}

	// Start overflow reporter
	fm.wg.Add(1)
	obs.Go("fanotify-overflow", fm.overflowReporter)

	// Resolve staged WordPress package files once their checksums land.
	fm.wg.Add(1)
	obs.Go("fanotify-wp-package", fm.stagedPackageLoop)

	// Start the self-deleting-dropper probe loop when the detector is enabled.
	if fm.dropper != nil {
		fm.wg.Add(1)
		obs.Go("fanotify-dropper", fm.dropperProbeLoop)
	}

	// C4 - create epoll instance, watch fanotify fd + pipe read end
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
		// #nosec G115 -- POSIX fd fits in int32 (rlimit caps fds at ~1024).
		Fd: int32(fm.fd),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] epoll_ctl(fanotify): %v\n", ts(), err)
		fm.runPollFallback(stopCh)
		return
	}

	// Add pipe read end to epoll (for stop signaling)
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fm.pipeFds[0], &unix.EpollEvent{
		Events: unix.EPOLLIN,
		// #nosec G115 -- POSIX fd fits in int32.
		Fd: int32(fm.pipeFds[0]),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] epoll_ctl(pipe): %v\n", ts(), err)
		fm.runPollFallback(stopCh)
		return
	}

	// Forward external stopCh to our internal mechanism
	obs.SafeGo("fanotify-stop-forward", func() {
		select {
		case <-stopCh:
			fm.Stop()
		case <-fm.stopCh:
		}
	})

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
			// #nosec G115 -- POSIX fd fits in int32; comparing against epoll event fd.
			if events[i].Fd == int32(fm.pipeFds[0]) {
				// Stop signal received via pipe
				fm.drainAndClose()
				return
			}

			// #nosec G115 -- POSIX fd fits in int32.
			if events[i].Fd == int32(fm.fd) {
				// fanotify events ready — single read per epoll wake
				fm.initQueueHealth()
				_, readErr := fm.kernelQueue.read(buf, fm.processEvents)
				if readErr != nil {
					if readErr != unix.EAGAIN && readErr != unix.EINTR {
						fmt.Fprintf(os.Stderr, "[%s] fanotify read error: %v\n", ts(), readErr)
					}
				}
			}
		}
	}
}

// runPollFallback is used when epoll setup fails; falls back to sleep-based polling.
func (fm *FileMonitor) runPollFallback(stopCh <-chan struct{}) {
	// Forward external stopCh to our internal mechanism
	obs.SafeGo("fanotify-stop-forward", func() {
		select {
		case <-stopCh:
			fm.Stop()
		case <-fm.stopCh:
		}
	})

	buf := make([]byte, 4096*24)

	for {
		select {
		case <-fm.stopCh:
			fm.drainAndClose()
			return
		default:
		}

		fm.initQueueHealth()
		_, err := fm.kernelQueue.read(buf, fm.processEvents)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			fmt.Fprintf(os.Stderr, "[%s] fanotify read error: %v\n", ts(), err)
			time.Sleep(1 * time.Second)
			continue
		}

	}
}

// processEvents parses a buffer of fanotify event metadata and dispatches each event.
func (fm *FileMonitor) processEvents(buf []byte) {
	offset := 0
	for offset+metadataSize <= len(buf) {
		// #nosec G103 -- fanotify delivers a packed binary stream on the
		// fd; we must reinterpret the byte buffer as the kernel struct.
		// The metadataSize bounds check above guarantees we have enough
		// bytes for the struct.
		event := (*fanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
		eventLen := int(event.EventLen)
		if eventLen < metadataSize || offset+eventLen > len(buf) {
			break
		}

		if event.Mask&unix.FAN_Q_OVERFLOW != 0 {
			fm.handleQueueOverflow()
		} else if event.Fd >= 0 {
			fm.handleEvent(int(event.Fd), event.Pid, event.Mask)
		}

		offset += eventLen
	}
}

// handleQueueOverflow reacts to a FAN_Q_OVERFLOW record. The kernel dropped
// events we will never see and gave us no fd, so we cannot reconcile the exact
// files. Count it, emit a rate-limited Warning so operators learn coverage was
// lost, and nudge the reconcile pass to rescan directories that also saw
// analyzer-queue drops during the same storm.
func (fm *FileMonitor) handleQueueOverflow() {
	fm.initQueueHealth()
	fm.kernelQueueHealth.Lose(time.Now(), 1)
	atomic.AddInt64(&fm.queueOverflows, 1)
	if fanotifyKernelOverflowTotal != nil {
		fanotifyKernelOverflowTotal.Inc()
	}
	fm.reportQueueOverflow()
	if fm.reconcileSig != nil {
		select {
		case fm.reconcileSig <- struct{}{}:
		default:
		}
	}
}

// reportQueueOverflow emits the kernel-overflow finding at most once per minute.
func (fm *FileMonitor) reportQueueOverflow() {
	fm.overflowReportMu.Lock()
	if !fm.lastOverflowReport.IsZero() && time.Since(fm.lastOverflowReport) < time.Minute {
		fm.overflowReportMu.Unlock()
		return
	}
	fm.lastOverflowReport = time.Now()
	fm.overflowReportMu.Unlock()
	fm.sendAlert(alert.Warning, "fanotify_kernel_overflow",
		"fanotify kernel event queue overflowed; file events were dropped by the kernel and cannot be recovered by path",
		"The kernel notification queue filled during a storm (bulk unzip, backup restore, or high-volume attack) and dropped events before the reader could drain them. Files touched during the overflow that are not written again are only covered by the next scheduled deep scan. A reconcile of directories that also saw analyzer-queue drops has been triggered.")
}

// drainAndClose drains the analyzerCh and waits for workers to finish.
// C1 - ensures no fd leak on shutdown.
func (fm *FileMonitor) drainAndClose() {
	fm.drainOnce.Do(func() {
		close(fm.analyzerCh)
		fm.wg.Wait()
		fm.discardReconcilePending()
		fm.stagedPackages().discardPending(time.Now())
		if fm.dropper != nil {
			fm.dropper.tr.discardPending(time.Now())
			clear(fm.dropper.attempts)
		}
		// Mark pipe as closed before actually closing, so Stop() won't
		// write to an already-closed fd (H2 fix).
		atomic.StoreInt32(&fm.pipeClosed, 1)
		_ = unix.Close(fm.pipeFds[0])
		_ = unix.Close(fm.pipeFds[1])
	})
}

// Stop signals the monitor to shut down.
// C2 - sync.Once ensures safe concurrent calls; does not close analyzerCh directly.
func (fm *FileMonitor) Stop() {
	fm.stopOnce.Do(func() {
		close(fm.stopCh)
		// Wake epoll so Run() exits and calls drainAndClose.
		// Only write if pipe hasn't been closed by drainAndClose yet.
		if atomic.LoadInt32(&fm.pipeClosed) == 0 {
			_, _ = unix.Write(fm.pipeFds[1], []byte{0})
		}
		// Close fanotify fd - causes any pending Read/EpollWait to return
		fm.initQueueHealth()
		_ = fm.kernelQueue.close()
	})
}

func (fm *FileMonitor) handleEvent(fd int, pid int32, mask uint64) {
	// Get the file path from the fd via /proc/self/fd/N
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		_ = unix.Close(fd)
		return
	}
	path = normalizeFanotifyEventPath(path)

	// M5 - skip directory events
	if strings.HasSuffix(path, "/") {
		_ = unix.Close(fd)
		return
	}

	// The dropper tracker also needs arbitrary executable names that have
	// no path-only content signal.
	fm.invalidateDropperPHPHandlerCache(path)
	contentInteresting := fm.isInteresting(path)
	dropperInteresting, phpExecutable := fm.isDropperInteresting(path, fd)
	if !contentInteresting && !dropperInteresting {
		_ = unix.Close(fd)
		return
	}

	// Send to analyzer pool (with backpressure)
	fm.initQueueHealth()
	ticket := fm.analyzerHealth.Begin(time.Now())
	select {
	case fm.analyzerCh <- fileEvent{
		queueTicket: ticket,
		path:        path, fd: fd, pid: pid, mask: mask,
		dropperOnly: !contentInteresting, phpExecutable: phpExecutable,
	}:
	default:
		// Queue full - drop event, count, and record the parent dir so the
		// reconcile pass in overflowReporter can rescan it. Without this
		// every file in a bulk burst past buffer capacity is invisible to
		// detection forever.
		ticket.Reject(time.Now())
		n := atomic.AddInt64(&fm.droppedEvents, 1)
		if fanotifyDroppedTotal != nil {
			fanotifyDroppedTotal.Inc()
		}
		if n%100 == 0 {
			fmt.Fprintf(os.Stderr, "[%s] fanotify: %d events dropped (analyzer queue full)\n", ts(), n)
		}
		fm.recordDroppedDir(path)
		fm.maybeTriggerEagerReconcile(n)
		_ = unix.Close(fd)
	}
}

// normalizeFanotifyEventPath removes procfs's synthetic " (deleted)" suffix
// when the event fd's directory entry was already unlinked. Linux does not
// disambiguate that marker from a literal filename suffix. Treat it as the
// kernel marker: otherwise an attacker can create a same-inode hardlink with
// the literal suffix and make an immediate self-delete miss the PHP path gate.
func normalizeFanotifyEventPath(path string) string {
	const deletedSuffix = " (deleted)"
	return strings.TrimSuffix(path, deletedSuffix)
}

// maybeTriggerEagerReconcile nudges overflowReporter to run reconcileDrops
// immediately when sustained drops cross eagerReconcileDropThreshold within
// a single minute window. Delegates to the free function so the trigger
// logic stays testable from a cross-platform test file.
func (fm *FileMonitor) maybeTriggerEagerReconcile(droppedSoFar int64) {
	signalEagerReconcile(fm.reconcileSig, droppedSoFar, eagerReconcileDropThreshold)
}

// isInteresting is the fast filter - zero I/O, pure string matching.
func (fm *FileMonitor) isInteresting(path string) bool {
	path = atomicWriteContentPath(path)

	lower := strings.ToLower(path)

	// PHP source files. This is intentionally broader than the executable-PHP
	// predicate used by the location and dropper checks: .phps is inert under a
	// stock handler, but still needs signature/YARA analysis while staged.
	if isPHPSourceExtension(filepath.Base(lower)) {
		return true
	}

	// Webshell extensions
	if strings.HasSuffix(lower, ".haxor") || strings.HasSuffix(lower, ".cgix") {
		return true
	}

	// CGI scripts in hosted trees - detect Perl/Python/Bash backdoors.
	// An explicit document root may live outside the platform's account homes.
	if fm.underAccountOrConfiguredDocRoot(path) {
		if strings.HasSuffix(lower, ".pl") || strings.HasSuffix(lower, ".cgi") ||
			strings.HasSuffix(lower, ".py") || strings.HasSuffix(lower, ".sh") ||
			strings.HasSuffix(lower, ".rb") {
			return true
		}
	}

	// .htaccess and .user.ini files (any location), and php.ini under a
	// configured or detected web root. An attacker plants php.ini files there
	// to weaken disable_functions.
	if strings.HasSuffix(lower, ".htaccess") || strings.HasSuffix(lower, ".user.ini") {
		return true
	}
	if filepath.Base(lower) == "php.ini" && pathMatchesWebRootPatterns(path, fm.webRootPatterns) {
		return true
	}

	// HTML files in an account or explicitly configured document tree.
	if fm.underAccountOrConfiguredDocRoot(path) &&
		(strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm")) {
		return true
	}

	// Images in an account or explicitly configured document tree. A real
	// image container is a working payload store: PHP appended to a valid
	// PNG still opens as a picture, and a one-line include elsewhere in the
	// site executes it. Admitting the write is what lets checkImagePayload
	// look at the bytes; the extension only routes the event, and the
	// verdict comes from the container magic, so a renamed payload is still
	// caught by the other branches.
	if fm.underAccountOrConfiguredDocRoot(path) && contenttype.IsImageExt(filepath.Ext(lower)) {
		return true
	}

	// Credential log files - known phishing harvest filenames
	base := filepath.Base(lower)
	if credentialLogNames[base] {
		return true
	}

	// ZIP archives in an account or explicitly configured document tree.
	if fm.underAccountOrConfiguredDocRoot(path) && strings.HasSuffix(lower, ".zip") {
		return true
	}

	// Anything in .config directories
	if strings.Contains(path, "/.config/") {
		return true
	}

	// User crontabs surfaced via the directory-scoped fanotify mark in
	// NewFileMonitor. Each write to /var/spool/cron/<user> dispatches to
	// checkCrontab in real time.
	if strings.HasPrefix(path, cronSpoolDir()+"/") {
		return true
	}

	// Executables in /tmp or /dev/shm
	if strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/dev/shm/") || strings.HasPrefix(path, "/var/tmp/") {
		return true
	}

	// PHP in sensitive directories that should never contain PHP
	if (strings.Contains(path, "/.ssh/") || strings.Contains(path, "/.cpanel/") ||
		strings.Contains(path, "/mail/") || strings.Contains(path, "/.gnupg/") ||
		strings.Contains(path, "/.cagefs/")) && isPHPExtension(strings.ToLower(filepath.Base(path))) {
		return true
	}

	return false
}

// underAccountRoot reports whether path sits inside a hosting account's tree.
// Falls back to the historical /home spelling when the platform offers no
// patterns, so an unconfigured plain-Linux host keeps the behaviour it had.
func (fm *FileMonitor) underAccountRoot(path string) bool {
	if len(fm.accountRootPatterns) == 0 {
		return strings.HasPrefix(path, "/home/")
	}
	return pathMatchesWebRootPatterns(path, fm.accountRootPatterns)
}

// underDocRoot reports whether path sits inside a served document root.
func (fm *FileMonitor) underDocRoot(path string) bool {
	if len(fm.docRootPatterns) == 0 {
		return strings.Contains(path, "/public_html/")
	}
	return pathMatchesWebRootPatterns(path, fm.docRootPatterns)
}

func (fm *FileMonitor) underAccountOrConfiguredDocRoot(path string) bool {
	return fm.underAccountRoot(path) ||
		(len(fm.docRootPatterns) > 0 && fm.underDocRoot(path))
}

func pathMatchesWebRootPatterns(path string, patterns []string) bool {
	dir := filepath.Clean(filepath.Dir(path))
	for {
		for _, pattern := range patterns {
			matched, err := filepath.Match(filepath.Clean(pattern), dir)
			if err == nil && matched {
				return true
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
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
// C1 - on channel close, drains remaining events and closes their fds.
func (fm *FileMonitor) analyzerWorker() {
	defer fm.wg.Done()
	for event := range fm.analyzerCh {
		fm.analyzeFileSafe(event)
		_ = unix.Close(event.fd)
	}
}

// fileAnalyzer analyzes one queued event. Var so tests can substitute a
// panicking analyzer.
var fileAnalyzer = (*FileMonitor).analyzeFile

// analyzeFileSafe runs one event and contains a panic: one crafted file
// must not restart the daemon and reopen the detection gap for every other
// write in flight. The caller still closes the event fd.
func (fm *FileMonitor) analyzeFileSafe(event fileEvent) {
	defer func() {
		if r := recover(); r != nil {
			fm.reportScannerPanic(event.path, r)
		}
	}()
	work := queuehealth.Work[fileEvent]{Value: event, Ticket: event.queueTicket}
	work.Process(func(queued fileEvent) { fileAnalyzer(fm, queued) })
}

// reportScannerPanic logs the panic with its stack, forwards it to
// observability and raises a critical finding at most once per ten minutes.
func (fm *FileMonitor) reportScannerPanic(path string, r interface{}) {
	obs.CaptureMsg("fanotify-analyzer", fmt.Sprintf("panic analyzing %s: %v", path, r))
	fmt.Fprintf(os.Stderr, "[%s] file monitor: recovered panic analyzing %s: %v\n%s", ts(), path, r, debug.Stack())
	fm.panicMu.Lock()
	defer fm.panicMu.Unlock()
	if !fm.lastPanicAt.IsZero() && time.Since(fm.lastPanicAt) < 10*time.Minute {
		return
	}
	fm.lastPanicAt = time.Now()
	fm.sendAlertWithPath(alert.Critical, "realtime_scanner_panic",
		fmt.Sprintf("Realtime scanner panicked on %s and skipped it: %v", path, r), "", path, "")
}

// readFromFd reads up to maxBytes from a file descriptor at position 0.
// C3 - avoids TOCTOU by reading from the original fanotify event fd.
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

const readCompleteMaxInterrupts = 8

// readExactSize reads exactly the snapshotted size. Its buffer is fixed before
// the first read, so a concurrently growing source cannot extend the loop; a
// bounded EINTR retry count also prevents a pathological signal storm from
// pinning an analyzer worker.
func readExactSize(size int64, maxBytes int, pread func([]byte, int64) (int, error)) []byte {
	if size <= 0 || maxBytes <= 0 || size > int64(maxBytes) {
		return nil
	}
	buf := make([]byte, int(size))
	interrupts := 0
	for off := 0; off < len(buf); {
		n, err := pread(buf[off:], int64(off))
		if n < 0 || n > len(buf)-off {
			return nil
		}
		if n > 0 {
			off += n
			interrupts = 0
		}
		if err != nil && !errors.Is(err, unix.EINTR) {
			return nil
		}
		if n > 0 {
			continue
		}
		if !errors.Is(err, unix.EINTR) {
			return nil
		}
		interrupts++
		if interrupts > readCompleteMaxInterrupts {
			return nil
		}
	}
	return buf
}

func sameReadSnapshot(before, after unix.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Size == after.Size &&
		before.Mtim == after.Mtim && before.Ctim == after.Ctim
}

// readCompleteFromFd returns a stable snapshot of the entire file behind fd
// when it fits within maxBytes. A short read, concurrent size/content change,
// or excessive interruption fails closed so whole-file recognizers never
// accept a stale prefix.
func readCompleteFromFd(fd, maxBytes int) []byte {
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil
	}
	buf := readExactSize(before.Size, maxBytes, func(p []byte, off int64) (int, error) {
		return unix.Pread(fd, p, off)
	})
	if buf == nil {
		return nil
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameReadSnapshot(before, after) {
		return nil
	}
	return buf
}

func isBenignPHPStubData(fd int, data []byte) bool {
	if len(data) == 0 {
		return false
	}
	complete := false
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err == nil {
		complete = st.Size <= int64(len(data))
	}
	return checks.IsBenignPHPStubBytesComplete(data, complete)
}

func isWPTranslationCacheData(fd int, data []byte) bool {
	if len(data) == 0 {
		return false
	}
	complete := false
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err == nil {
		complete = st.Size <= int64(len(data))
	}
	return checks.IsWPTranslationCacheBytesComplete(data, complete)
}

// readTailFromFd reads the last maxBytes of a file via its fd using pread.
// Returns nil if the file is smaller than maxBytes (head scan already covers it).
func readTailFromFd(fd int, maxBytes int) []byte {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil
	}
	size := stat.Size
	if size <= int64(maxBytes) {
		return nil // head read already covers the entire file
	}
	offset := size - int64(maxBytes)
	buf := make([]byte, maxBytes)
	n, err := unix.Pread(fd, buf, offset)
	if n <= 0 || (err != nil && n == 0) {
		return nil
	}
	return buf[:n]
}

// resolveProcessInfo reads /proc/<pid>/comm and /proc/<pid>/status
// to build a "pid=N cmd=name uid=N" string for alert enrichment.
// Returns empty string on any error (process may have exited).
func resolveProcessInfo(pid int32) string {
	if pid <= 0 {
		return ""
	}
	procDir := fmt.Sprintf("/proc/%d", pid)

	// Read process name
	// #nosec G304 -- /proc/<pid>/comm; kernel pseudo-FS, pid is int32 from fanotify event.
	comm, err := os.ReadFile(procDir + "/comm")
	if err != nil {
		return ""
	}
	name := strings.TrimSpace(string(comm))

	info := fmt.Sprintf("pid=%d cmd=%s", pid, name)

	// Read UID from status to map to cPanel username
	// #nosec G304 -- /proc/<pid>/status; kernel pseudo-FS.
	statusData, err := os.ReadFile(procDir + "/status")
	if err != nil {
		return info
	}
	for _, line := range strings.Split(string(statusData), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info += fmt.Sprintf(" uid=%s", fields[1])
			}
			break
		}
	}

	return info
}

func (fm *FileMonitor) analyzeFile(event fileEvent) {
	path := event.path
	contentPath := atomicWriteContentPath(path)
	name := filepath.Base(contentPath)
	nameLower := strings.ToLower(name)
	imageInHostedTree := contenttype.IsImageExt(filepath.Ext(nameLower)) && fm.underAccountOrConfiguredDocRoot(contentPath)

	// Resolve process info from PID (best-effort - process may have exited)
	procInfo := resolveProcessInfo(event.pid)

	// Snapshot this write as a possible self-deleting dropper before the
	// per-type checks below can early-return. Reads are positional (Pread/
	// Fstat/Statx) so they do not disturb the fd for later content checks.
	cand := fm.observeDropperCandidate(event, procInfo)
	markDropperContentSuspicious := func() {
		if cand == nil {
			return
		}
		cand.ContentSuspicious = true
		if !fm.dropper.tr.Refresh(*cand) {
			fm.dropper.admit(*cand)
		}
	}

	// Some events are admitted only for dropper tracking. Handler-mapped PHP
	// still needs the normal PHP scanner; arbitrary executables retain the
	// strongest cheap content signal for the later deletion verdict.
	if event.dropperOnly {
		if event.phpExecutable {
			if fm.checkPHPContent(event.fd, path, procInfo) {
				markDropperContentSuspicious()
			}
		} else if cand != nil && looksLikePHPWebshell(cand.Head) {
			markDropperContentSuspicious()
		}
		return
	}

	// H2 - suppression path matching using filepath.Match. Read the live config
	// (config.Active via currentCfg) so a SIGHUP change to suppressions.ignore_paths
	// takes effect without a restart, matching the rest of this analyzer.
	for _, ignore := range fm.currentCfg().Suppressions.IgnorePaths {
		if matchSuppression(ignore, path) {
			return
		}
	}

	// Skip unmodified WordPress core and plugin files: the hash matches the
	// official wordpress.org checksums for the version the install or
	// package declares. Stops signature/YARA FPs on stock code, installed or
	// staged: a realtime Critical feeds inline quarantine, and a byte-for-byte
	// copy of the official release is not what that is for. A cache miss
	// triggers a background fetch and falls through to rule evaluation; the
	// description is kept for the update-staging branch below, which judges
	// a staged package by these verdicts. For atomic writes, the intended
	// basename only selects the checksum entry. Trust requires hashing the
	// complete original event descriptor.
	var wpVerdict wpcheck.Verification
	if fm.wpCache != nil {
		wpVerdict = fm.wpCache.VerifyFile(event.fd, contentPath)
		if wpVerdict.Verdict == wpcheck.VerdictVerified {
			return
		}
	}

	// User crontab written under /var/spool/cron/<user>. Scan content
	// from the event fd via the shared deep matcher and emit Critical on
	// any hit. The polled CheckCrontabs run still tracks root crontab
	// hash drift, so we skip root here to avoid duplicate signal.
	if strings.HasPrefix(path, cronSpoolDir()+"/") {
		fm.checkCrontab(event.fd, path, procInfo)
		return
	}

	// Location-based severity escalation: PHP in dirs that should NEVER have PHP
	if isPHPExtension(nameLower) {
		for _, sensitive := range []string{"/.ssh/", "/.cpanel/", "/mail/", "/.gnupg/", "/.cagefs/"} {
			if strings.Contains(path, sensitive) {
				fm.sendAlertWithPath(alert.Critical, "php_in_sensitive_dir_realtime",
					fmt.Sprintf("PHP file in critical directory: %s", path),
					fmt.Sprintf("PHP should never exist in %s - likely webshell or backdoor", sensitive), path, procInfo)
				return
			}
		}
	}

	// Known webshell filenames (M1 - package-level var). Filename alone is
	// too weak: WordPress core ships wp-includes/Text/Diff/Engine/shell.php
	// (the Pear Text_Diff library using shell_exec to call Unix `diff`).
	// Confirm with content: the file must also exhibit webshell markers
	// (request superglobal flowing into a dangerous function, or an
	// eval/assert wrapping a base64/gzinflate decoder).
	if knownWebshells[nameLower] {
		recordReadTruncation(event.fd, 65536, "phpcontent_inline")
		if data := readFromFd(event.fd, 65536); looksLikePHPWebshell(data) {
			markDropperContentSuspicious()
			fm.sendAlertWithPath(alert.Critical, "webshell_realtime",
				fmt.Sprintf("Webshell file created: %s", path), "", path, procInfo)
			return
		}
	}

	// Webshell extensions
	if strings.HasSuffix(nameLower, ".haxor") || strings.HasSuffix(nameLower, ".cgix") {
		fm.sendAlertWithPath(alert.Critical, "webshell_realtime",
			fmt.Sprintf("Suspicious CGI file created: %s", path), "", path, procInfo)
		return
	}

	// .htaccess modification - check for injection (C3 - read from fd).
	// Checked before the /tmp early-return so a malicious .htaccess anywhere
	// (including /tmp) is still analyzed for dangerous directives.
	if nameLower == ".htaccess" {
		fm.checkHtaccess(event.fd, path, procInfo)
		return
	}

	// .user.ini modification - check for dangerous PHP settings (C3 - read from fd).
	// Also checked before /tmp so malicious .user.ini is detected anywhere.
	if nameLower == ".user.ini" || nameLower == "php.ini" {
		fm.checkUserINI(event.fd, path, procInfo)
		return
	}

	// Executables in .config - checked before the /tmp block so a miner
	// dropped at /tmp/.config/* is flagged as executable_in_config_realtime
	// (more specific) rather than executable_in_tmp_realtime.
	// Uses unix.Fstat on the event fd (not os.Stat by path) for TOCTOU
	// safety: an attacker cannot chmod -x or swap the file after the event.
	if strings.Contains(path, "/.config/") {
		var cfgStat unix.Stat_t
		if err := unix.Fstat(event.fd, &cfgStat); err == nil {
			isDir := cfgStat.Mode&unix.S_IFMT == unix.S_IFDIR
			if !isDir && cfgStat.Mode&0111 != 0 {
				fm.sendAlertWithPath(alert.Critical, "executable_in_config_realtime",
					fmt.Sprintf("Executable created in .config: %s", path),
					fmt.Sprintf("Size: %d", cfgStat.Size), path, procInfo)
			}
		}
		if !imageInHostedTree {
			return
		}
	}

	// Executables in /tmp or /dev/shm - detect dropped malware/miners
	// Uses unix.Fstat on event fd for TOCTOU safety (attacker can't chmod -x after event)
	if strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/dev/shm/") || strings.HasPrefix(path, "/var/tmp/") {
		var tmpStat unix.Stat_t
		if err := unix.Fstat(event.fd, &tmpStat); err == nil {
			isDir := tmpStat.Mode&unix.S_IFMT == unix.S_IFDIR
			isExec := tmpStat.Mode&0111 != 0
			if !isDir && isExec {
				// Skip known root-owned work directories:
				// - cPanel: SpamAssassin compiles .so regex modules, UPCP stages scripts
				// - dracut: rebuilds initramfs after kernel updates, copies system binaries
				// Non-root files in these paths are still suspicious.
				isCpanelWork := strings.Contains(path, "/cpanel.TMP.work.") || strings.Contains(path, "/cPanel-")
				isDracutWork := strings.Contains(path, "/dracut.")
				if (isCpanelWork || isDracutWork) && tmpStat.Uid == 0 {
					// Root-owned executable in system work dir - legitimate, skip
				} else {
					// Root-owned drops from a live package transaction
					// (e.g. weak-modules extracting initramfs via cpio
					// after a kernel update) are rescored to Warning,
					// never suppressed. See demoteTmpExec for the gates.
					severity := alert.Critical
					details := fmt.Sprintf("Size: %d, Mode: %04o, UID: %d", tmpStat.Size, tmpStat.Mode&0777, tmpStat.Uid)
					if ok, reason := tmpExecDemote(tmpStat.Uid, event.pid, time.Now()); ok {
						severity = alert.Warning
						details += " [demoted: " + reason + "]"
					}
					fm.sendAlertWithPath(severity, "executable_in_tmp_realtime",
						fmt.Sprintf("Executable created in %s: %s", filepath.Dir(path), path),
						details, path, procInfo)
				}
			}
		}
		// Hosted images still need payload checks when the configured root
		// lives in a temporary directory, as do PHP source files anywhere.
		if !isPHPSourceExtension(nameLower) && !imageInHostedTree {
			return
		}
	}

	// PHP in uploads directories.
	// Any PHP file here is anomalous: /wp-content/uploads/ is meant for
	// media, not code. Plugin-update temp dirs are recognised structurally
	// via looksLikePluginUpdate only after content checks have had first
	// refusal, so a decoy update directory cannot downgrade a webshell.
	// Operators suppress legitimate caching daemons through the path-scoped
	// suppressions_api, not an implicit substring allowlist in the daemon.
	if strings.Contains(path, "/wp-content/uploads/") && isPHPExtension(nameLower) {
		// Content-aware severity: PHP in uploads is anomalous but not
		// always malicious (TinyMCE smile_fonts/charmap.php is glyph
		// data shipped by WP's bundled editor). Emit Critical for
		// direct webshell markers, otherwise run the broader PHP
		// content/signature/YARA path before downgrading clean PHP to
		// a Warning.
		recordReadTruncation(event.fd, 65536, "phpcontent_uploads")
		data := readFromFd(event.fd, 65536)
		if looksLikePHPWebshell(data) {
			markDropperContentSuspicious()
			fm.sendAlertWithPath(alert.Critical, "php_in_uploads_realtime",
				fmt.Sprintf("PHP file created in uploads: %s", path),
				"Webshell markers in content (request superglobal -> dangerous function, or eval/assert + decoder chain)",
				path, procInfo)
		} else {
			if fm.checkPHPContent(event.fd, path, procInfo) {
				markDropperContentSuspicious()
				return
			}
			// Content-shape gate: file whose reachable code is
			// whitespace+comments, or that terminates with
			// die/exit/__halt_compiler before any statement,
			// cannot execute attacker-controlled code via web
			// request. BackWPup writes its working-job and
			// folder-cache state files this way. The earlier
			// signature/YARA pass and the path-only warning
			// below are the layers that fire on real droppers;
			// a structurally inert stub adds no signal.
			if isBenignPHPStubData(event.fd, data) {
				return
			}
			if looksLikePluginUpdate(path) {
				// Verified plugin update - emit one low-severity alert per temp directory.
				uploadsIdx := strings.Index(path, "/wp-content/uploads/")
				afterUploads := path[uploadsIdx+len("/wp-content/uploads/"):]
				tempDir := afterUploads
				if slashIdx := strings.Index(afterUploads, "/"); slashIdx > 0 {
					tempDir = afterUploads[:slashIdx]
				}
				updateDir := path[:uploadsIdx] + "/wp-content/uploads/" + tempDir
				fm.sendAlertWithPath(alert.Warning, "php_in_uploads_realtime",
					fmt.Sprintf("Plugin update in uploads: %s", updateDir),
					"Verified: matching plugin exists in plugins/", updateDir, procInfo)
				return
			}
			// Suppress the path-only "anomalous location" warning
			// when the file is structurally a duplicate (cPanel
			// restore staging) or a known plugin probe shape that
			// never carries executable input. Signature/YARA scans
			// already ran above, so any real malicious content is
			// reported through its own pipeline.
			if looksLikeCpanelRestoreStaging(path) {
				return
			}
			if looksLikeWPOptimizeProbe(path, data) {
				return
			}
			fm.sendAlertWithPath(alert.Warning, "php_in_uploads_realtime",
				fmt.Sprintf("PHP file in uploads (no webshell markers): %s", path),
				"Anomalous location for PHP, but content is clean",
				path, procInfo)
		}
		return
	}

	// PHP in languages/upgrade directories.
	// Path-only Critical buried real alerts under location noise (WPML
	// translation queues, WP auto-update staging). Run content analysis
	// on every file -- a real rule fires Critical, clean real code gets a
	// Warning, and inert stubs stay quiet. No filename allowlist: an attacker
	// must not be able to hide a backdoor by naming it like a translation or
	// index file.
	if (strings.Contains(path, "/wp-content/languages/") || strings.Contains(path, "/wp-content/upgrade/")) &&
		isPHPExtension(nameLower) {
		if fm.checkPHPContent(event.fd, path, procInfo) {
			markDropperContentSuspicious()
		} else {
			// Every staged file reaches content analysis first. Its original
			// digest then decides the path-only warning, even for inert files
			// absent from the official manifest.
			if fm.handleStagedPackageFile(path, wpVerdict, procInfo) {
				return
			}
			// Translation caches and comment-only stubs require a stable,
			// complete body. A no-argument PHP terminator is safe from a
			// prefix because all following bytes are unreachable, so retain
			// the old bounded-head fallback for oversized files.
			data := readCompleteFromFd(event.fd, checks.MaxInertPHPScanBytes)
			if data != nil && checks.IsBenignPHPStubBytesComplete(data, true) {
				return
			}
			if data == nil && checks.IsBenignPHPStubBytesComplete(readFromFd(event.fd, 65536), false) {
				return
			}
			// WordPress 6.5+ writes *.l10n.php translation caches here as pure
			// data return arrays. Suppress by content structure, not filename.
			if isWPTranslationCacheData(event.fd, data) {
				return
			}
			fm.sendAlertWithPath(alert.Warning, "php_in_sensitive_dir_realtime",
				fmt.Sprintf("PHP file created in sensitive WP directory (content clean): %s", path), "", path, procInfo)
		}
		return
	}

	// PHP content analysis (C3 - read from fd; M4 - 32KB scan size).
	// .htaccess, .user.ini, and .config executable checks are handled
	// earlier in this function (before the /tmp early-return) so specific
	// file types take precedence over the /tmp generic block.
	if isPHPSourceExtension(nameLower) {
		if fm.checkPHPContent(event.fd, path, procInfo) {
			markDropperContentSuspicious()
		}
		return
	}

	// HTML phishing page detection (uses event fd for content, unix.Fstat for size)
	if strings.HasSuffix(nameLower, ".html") || strings.HasSuffix(nameLower, ".htm") {
		fm.checkHTMLPhishing(event.fd, path, procInfo)
		return
	}

	// PHP carried inside an image file (uses event fd for content).
	if contenttype.IsImageExt(filepath.Ext(nameLower)) {
		// Handler-mapped images previously entered through dropperOnly and
		// received the full PHP scan. Content admission must retain it.
		if event.phpExecutable && fm.checkPHPContent(event.fd, path, procInfo) {
			markDropperContentSuspicious()
			return
		}
		if fm.checkImagePayload(event.fd, path, procInfo) {
			markDropperContentSuspicious()
		}
		return
	}

	// Credential log files (content read from the event fd)
	if credentialLogNames[nameLower] {
		fm.checkCredentialLog(event.fd, path, procInfo)
		return
	}

	// Phishing kit ZIP archives (path-based)
	if strings.HasSuffix(nameLower, ".zip") {
		fm.checkPhishingZip(path, nameLower, procInfo)
		return
	}

	// CGI scripts in web-accessible directories (Perl, Python, Bash, Ruby)
	// Detect backdoor toolkits like LEVIATHAN that use non-PHP scripts.
	if fm.underAccountOrConfiguredDocRoot(path) && isCGIExtension(nameLower) {
		fm.checkCGIBackdoor(event.fd, path, procInfo)
		return
	}
}

// Structural exclusions for checkHtaccess. Both anchor to the actual
// directive or regex context, not to loose substrings that an attacker
// can paste anywhere on the line.
var (
	// Legit auto_(prepend|append)_file directive targets: known product
	// files shipped by security plugins. Match is anchored to the
	// directive argument, so a trailing "# litespeed" comment cannot
	// forge safety.
	htaccessAutoPrependSafeTarget = regexp.MustCompile(
		`(?i)auto_(?:prepend|append)_file\s*=?\s*['"]?(?:[^\s'"]*/)?` +
			`(?:wordfence-waf|sucuri|advanced-headers)\.php(?:['"]|\s|$)`,
	)
	// Apache mod_rewrite directives. base64_decode / eval( appearing
	// inside a RewriteCond or RewriteRule is a pattern in an attack-query
	// blocklist (e.g. Really Simple SSL hardening), not PHP code.
	htaccessRewriteDirective = regexp.MustCompile(
		`(?i)^\s*Rewrite(?:Cond|Rule)\s`,
	)
)

// checkCrontab scans a freshly-written /var/spool/cron/<user> file for the
// known persistence-marker patterns (literal + base64-decoded). Reads from
// the event fd, not the path, so an attacker swapping the file post-event
// cannot redirect us. Root crontab drift is tracked separately via
// hash-baseline by the polled CheckCrontabs.
func (fm *FileMonitor) checkCrontab(fd int, path, procInfo string) {
	user := filepath.Base(path)
	if user == "" || user == "root" || user == filepath.Base(cronSpoolDir()) {
		return
	}
	recordReadTruncation(fd, 65536, "crontab")
	data := readFromFd(fd, 65536)
	if data == nil {
		return
	}
	matched := checks.MatchCrontabPatternsDeep(string(data), fm.currentCfg())
	if len(matched) == 0 {
		return
	}
	fm.sendAlertWithPath(alert.Critical, "suspicious_crontab",
		fmt.Sprintf("Suspicious crontab written for user %s: %v", user, matched),
		fmt.Sprintf("File: %s\nPatterns matched: %v", path, matched),
		path, procInfo)
}

// checkHtaccess reads .htaccess content from the event fd and checks for injection.
// C3 - reads from fd, not path.
func (fm *FileMonitor) checkHtaccess(fd int, path, procInfo string) {
	recordReadTruncation(fd, htaccessRealtimeMaxBytes, "htaccess")
	data := readFromFd(fd, htaccessRealtimeMaxBytes+1)
	if data == nil {
		return
	}
	if len(data) > htaccessRealtimeMaxBytes {
		fm.sendAlertWithPath(alert.High, "htaccess_injection_realtime",
			fmt.Sprintf(".htaccess too large to inspect in real time: %s", path),
			"The file exceeds the real-time .htaccess scan limit and may hide malicious directives.",
			path, procInfo)
		return
	}

	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)

		// auto_prepend_file / auto_append_file: suspicious unless the
		// directive target matches a known-legit security plugin file.
		if strings.Contains(lower, "auto_prepend_file") || strings.Contains(lower, "auto_append_file") {
			if htaccessAutoPrependSafeTarget.MatchString(line) {
				continue
			}
			fm.sendAlertWithPath(alert.High, "htaccess_injection_realtime",
				fmt.Sprintf("Suspicious .htaccess modification: %s", path),
				"auto_prepend_file/auto_append_file target not recognised", path, procInfo)
			continue
		}

		// eval( / base64_decode outside a RewriteCond/RewriteRule is a
		// tamper signal: .htaccess is not a PHP execution context, so
		// the only legit appearance of these tokens is as regex patterns
		// inside mod_rewrite attack-blocklists.
		if strings.Contains(lower, "eval(") || strings.Contains(lower, "base64_decode") {
			if htaccessRewriteDirective.MatchString(line) {
				continue
			}
			fm.sendAlertWithPath(alert.High, "htaccess_injection_realtime",
				fmt.Sprintf("Suspicious .htaccess modification: %s", path),
				"PHP function reference outside RewriteCond/RewriteRule", path, procInfo)
		}
	}

	// Run the full .htaccess detector registry so realtime detection matches
	// the depth of the scheduled scan: CGI-handler webshell arming, ModSecurity
	// disable, PHP-in-uploads, handler remaps, cloaks, and redirect hijacks.
	hardened, _ := checks.AuditHtaccessContent(path, data)
	for _, f := range hardened {
		fm.sendAlertWithPath(f.Severity, f.Check, f.Message, f.Details, path, procInfo)
	}

	// Run signature/YARA scanning on .htaccess content
	fm.runEventSignatureScan(fd, data, path, ".htaccess", procInfo)
}

// checkUserINI reads the event fd so a path replacement cannot change the
// content being analyzed.
func (fm *FileMonitor) checkUserINI(fd int, path, procInfo string) {
	recordReadTruncation(fd, checks.PHPConfigMaxBytes, "user_ini")
	data := readFromFd(fd, checks.PHPConfigMaxBytes+1)
	if data == nil {
		return
	}
	if len(data) > checks.PHPConfigMaxBytes {
		fm.sendAlertWithPath(alert.High, "php_config_realtime",
			fmt.Sprintf("PHP configuration too large to inspect: %s", path),
			"The file exceeds the PHP configuration scan limit and may hide dangerous directives.",
			path, procInfo)
		return
	}
	if dangerous := checks.PHPConfigSecurityBypasses(string(data)); len(dangerous) > 0 {
		fm.sendAlertWithPath(alert.Critical, "php_config_realtime",
			fmt.Sprintf("PHP security configuration weakened: %s", path),
			fmt.Sprintf("Dangerous settings:\n- %s", strings.Join(dangerous, "\n- ")), path, procInfo)
		return
	}

	// Run signature/YARA scanning on PHP configuration content.
	fm.runEventSignatureScan(fd, data, path, ".ini", procInfo)
}

// checkPHPContent reads PHP content from the event fd and checks for malicious patterns.
// C3 - reads from fd, not path. M4 - 32KB scan size.
func (fm *FileMonitor) checkPHPContent(fd int, path, procInfo string) bool {
	recordReadTruncation(fd, 32768, "php_check")
	data := readFromFd(fd, 32768)
	if data == nil {
		return false
	}
	content := strings.ToLower(string(data))

	if looksLikePHPWebshell(data) {
		fm.sendAlertWithPath(alert.Critical, "webshell_content_realtime",
			fmt.Sprintf("Webshell pattern detected: %s", path),
			"Request input reaches a dangerous PHP execution primitive", path, procInfo)
		return true
	}

	// Remote payload fetching — paste sites are always suspicious.
	// GitHub raw URLs only flag when combined with a dangerous call on
	// the same line (legitimate plugins use GitHub for update checks).
	pasteURLs := []string{"pastebin.com/raw", "paste.ee/r/", "ghostbin.co/paste/", "hastebin.com/raw/"}
	for _, p := range pasteURLs {
		if strings.Contains(content, p) {
			fm.sendAlertWithPath(alert.Critical, "php_dropper_realtime",
				fmt.Sprintf("PHP dropper with paste site URL: %s", path),
				fmt.Sprintf("Fetches from: %s", p), path, procInfo)
			return true
		}
	}
	githubURLs := []string{"gist.githubusercontent.com", "raw.githubusercontent.com"}
	dangerousFns := []string{"file_put_contents(", "fwrite(", "shell_", "passthru(", "popen("}
	for _, gh := range githubURLs {
		if !strings.Contains(content, gh) {
			continue
		}
		for _, line := range strings.Split(content, "\n") {
			if !strings.Contains(line, gh) {
				continue
			}
			for _, fn := range dangerousFns {
				if strings.Contains(line, fn) {
					fm.sendAlertWithPath(alert.Critical, "php_dropper_realtime",
						fmt.Sprintf("PHP dropper fetching from GitHub with dangerous call: %s", path),
						fmt.Sprintf("URL: %s, Function: %s", gh, fn), path, procInfo)
					return true
				}
			}
		}
	}

	// eval + decoder combo — require same-line nesting to avoid FPs on
	// legitimate plugins that use these functions in unrelated contexts.
	evalStr := "eval("     // search target for PHP eval function calls
	assertStr := "assert(" // search target for PHP assert function calls
	decoders := []string{"base64_decode", "gzinflate", "gzuncompress", "str_rot13", "gzdecode"}
	for _, line := range strings.Split(content, "\n") {
		lineHasEval := strings.Contains(line, evalStr) || strings.Contains(line, assertStr)
		if !lineHasEval {
			continue
		}
		for _, dec := range decoders {
			if strings.Contains(line, dec) {
				fm.sendAlertWithPath(alert.Critical, "obfuscated_php_realtime",
					fmt.Sprintf("Obfuscated PHP detected: %s", path),
					fmt.Sprintf("PHP code execution with %s on same line", dec), path, procInfo)
				return true
			}
		}
	}

	// Fragmented base64 evasion: $a="base"; $b="64_decode"; $c=$a.$b;
	if strings.Contains(content, "\"base\"") || strings.Contains(content, "'base'") {
		if strings.Contains(content, "64_dec") && strings.Contains(content, evalStr) {
			fm.sendAlertWithPath(alert.Critical, "obfuscated_php_realtime",
				fmt.Sprintf("Fragmented base64_decode evasion detected: %s", path),
				"base64_decode function name split across string variables", path, procInfo)
			return true
		}
	}

	// Massive variable concatenation payload ($z .= "xxxx"; repeated thousands of times)
	concatCount := strings.Count(content, ".= \"")
	if concatCount > 50 && strings.Contains(content, evalStr) {
		fm.sendAlertWithPath(alert.Critical, "obfuscated_php_realtime",
			fmt.Sprintf("Concatenation payload detected: %s (%d concat ops)", path, concatCount),
			"Variable built from hundreds of string concatenations then executed", path, procInfo)
		return true
	}

	// Shell execution with request input
	// Uses containsFunc to avoid substring false positives
	// (e.g. "WP_Filesystem(" matching "exec(", "preg_match(" matching "exec(")
	shellFuncs := []string{"system(", "passthru(", "exec(", "shell_exec(", "popen("}
	requestVars := []string{"$_request", "$_post", "$_get", "$_cookie", "$_server"}
	hasShell := false
	hasInput := false
	for _, sf := range shellFuncs {
		if containsFunc(content, sf) {
			hasShell = true
		}
	}
	for _, rv := range requestVars {
		if strings.Contains(content, rv) {
			hasInput = true
		}
	}
	if hasShell && hasInput {
		// Require shell function + request variable on the SAME line.
		// Same-line narrowing is the actual detection: admin panels with
		// both tokens in unrelated contexts stay quiet because they never
		// co-occur on one line. A file-wide allowlist (e.g. "skip when
		// 'wp_filesystem' appears anywhere") would be forgeable by any
		// webshell that pastes the token into a comment.
		for _, line := range strings.Split(content, "\n") {
			lineHasShell := false
			lineHasInput := false
			for _, sf := range shellFuncs {
				if containsFunc(line, sf) {
					lineHasShell = true
					break
				}
			}
			for _, rv := range requestVars {
				if strings.Contains(line, rv) {
					lineHasInput = true
					break
				}
			}
			if lineHasShell && lineHasInput {
				fm.sendAlertWithPath(alert.Critical, "webshell_content_realtime",
					fmt.Sprintf("Webshell pattern detected: %s", path),
					fmt.Sprintf("Shell execution with request input on same line: %s", strings.TrimSpace(line)), path, procInfo)
				return true
			}
		}
	}

	// Tail scan: for large files, also check the last 32KB.
	// Attackers append payloads (eval+base64) at the end of legitimate PHP files,
	// beyond the head scan window. Only do the cheap heuristic checks, not full
	// signature scanning (which would be too slow on every large PHP file).
	if tailData := readTailFromFd(fd, 32768); tailData != nil {
		tail := strings.ToLower(string(tailData))

		// Check for eval+decoder on same line in tail
		for _, line := range strings.Split(tail, "\n") {
			lineHasEval := strings.Contains(line, evalStr) || strings.Contains(line, assertStr)
			if !lineHasEval {
				continue
			}
			for _, dec := range decoders {
				if strings.Contains(line, dec) {
					fm.sendAlertWithPath(alert.Critical, "obfuscated_php_realtime",
						fmt.Sprintf("Obfuscated PHP appended to file tail: %s", path),
						fmt.Sprintf("PHP code execution with %s found at end of file", dec), path, procInfo)
					return true
				}
			}
		}

		// Fragmented base64 in tail
		if strings.Contains(tail, "\"base\"") || strings.Contains(tail, "'base'") {
			if strings.Contains(tail, "64_dec") && strings.Contains(tail, evalStr) {
				fm.sendAlertWithPath(alert.Critical, "obfuscated_php_realtime",
					fmt.Sprintf("Fragmented base64_decode evasion in file tail: %s", path),
					"Payload appended at end of legitimate PHP file", path, procInfo)
				return true
			}
		}

		// Concat payload with eval in tail
		tailConcatCount := strings.Count(tail, ".= \"")
		if tailConcatCount > 50 && strings.Contains(tail, evalStr) {
			fm.sendAlertWithPath(alert.Critical, "obfuscated_php_realtime",
				fmt.Sprintf("Concatenation payload in file tail: %s (%d concat ops)", path, tailConcatCount),
				"Payload appended at end of legitimate PHP file", path, procInfo)
			return true
		}
	}

	// Skip signature/YARA scanning for verified CMS core files.
	// The wp_core periodic check validates files against official checksums;
	// if a file's hash matches a known-clean core file, signature matches
	// on it are false positives (e.g. $_POST in wp-includes, mail() in
	// PHPMailer, fsockopen() in POP3.php).
	// Hashed from the event descriptor, not by re-opening the path: the path
	// can resolve to clean core content while the bytes just scanned were
	// malicious, which would skip signature and YARA scanning for the file
	// that was actually examined.
	contentSize := int64(len(data))
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err == nil && stat.Size > contentSize {
		contentSize = stat.Size
	}
	if !checks.CMSCacheEmpty() && checks.CMSCacheMayContainSize(contentSize) &&
		checks.IsVerifiedCMSHash(hashEventFD(fd, data, contentSize)) {
		return false
	}

	// External signature + YARA scanning. The YAML engine sees the complete
	// event-file size even though realtime analysis scans a bounded prefix, so
	// per-rule file-size limits cannot be defeated by prefix truncation.
	return fm.runSignatureScanWithSize(data, contentSize, path, filepath.Ext(path), procInfo, scannedIdentity(fd))
}

// Images fitting the combined read budget are scanned in one piece so a
// payload cannot straddle two independently evaluated windows. Larger files
// get a head and tail window; the middle is left to the deep scan, subject
// to thresholds.full_scan_max_file_mb.
const (
	imagePayloadHeadBytes = 65536
	imagePayloadTailBytes = 65536
)

// checkImagePayload looks for executable PHP inside a file served as an image.
// Returns true when a finding was raised.
//
// Two shapes reach the same verdict. A polyglot is a genuine image container
// with PHP appended or stored in a metadata chunk: it renders in a browser,
// passes an upload filter that trusts getimagesize, and executes the moment
// any PHP file includes its path. A file that only wears an image name and
// holds PHP source is the same backdoor without the disguise. Neither is
// legitimate under a served tree, so the container is reported as context
// rather than used as a gate.
//
// A PHP opening tag by itself is not evidence. Plugin screenshots quote one
// in their description chunks, so an execution, inclusion or remote-fetch
// construct is required alongside it.
func (fm *FileMonitor) checkImagePayload(fd int, path, procInfo string) bool {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= 0 {
		return false
	}
	const readBudget = imagePayloadHeadBytes + imagePayloadTailBytes
	headBytes := imagePayloadHeadBytes
	if st.Size <= readBudget {
		headBytes = int(st.Size)
	}
	recordReadTruncation(fd, readBudget, "image_payload")
	head := readFromFd(fd, headBytes)
	if len(head) == 0 {
		return false
	}
	container, _ := contenttype.ImageContainer(head)

	evidence, found := phpExecutableContent(head)
	if !found && st.Size > readBudget {
		// The container verdict came from the head, so the tail is examined
		// for the payload alone.
		if tail := readTailFromFd(fd, imagePayloadTailBytes); tail != nil {
			evidence, found = phpExecutableContent(tail)
		}
	}
	if !found {
		return false
	}

	describedContainer := container
	if describedContainer == "" {
		describedContainer = "none (file is not a valid image)"
	}
	fm.sendAlertWithPath(alert.Critical, "php_in_image_realtime",
		fmt.Sprintf("Executable PHP inside image file: %s", path),
		fmt.Sprintf("Container: %s\nEvidence: %s\nRemediation: this path is the payload; find and remove the PHP file that includes it", describedContainer, evidence),
		path, procInfo)
	return true
}

// checkHTMLPhishing reads an HTML file and checks for phishing indicators:
// brand impersonation + credential input + redirect/exfiltration.
// Uses event fd for content read and unix.Fstat for size (TOCTOU-safe).
func (fm *FileMonitor) checkHTMLPhishing(fd int, path, procInfo string) {
	// Only check files in web-accessible directories.
	//
	// No path-allowlist below this point: the content gates (credential
	// inputs + brand impersonation + exfil/trust-badge) reject legitimate
	// framework HTML on their own. A previous allowlist for /wp-admin/,
	// /wp-content/themes/, /wp-content/plugins/, /node_modules/, /vendor/,
	// /.well-known/ let an attacker who compromised any of those dirs drop
	// a credential-harvesting page with full suppression.
	if !fm.underDocRoot(path) {
		return
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return
	}
	size := stat.Size
	if size < 500 || size > 500000 {
		return
	}

	recordReadTruncation(fd, 16384, "html_phishing")
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
			fmt.Sprintf("Size: %d bytes", size), path, procInfo)
		return
	}

	// Run signature/YARA scanning on HTML content not caught by phishing heuristics
	fm.runEventSignatureScan(fd, data, path, ".html", procInfo)
}

// checkCredentialLog reads a text file and checks if it contains harvested
// email:password pairs - output from an active phishing kit. The path is used
// only for the suppression/location checks; the content is read from the
// fanotify event fd (not re-opened by path) so an attacker cannot swap the
// file between the event and the read.
func (fm *FileMonitor) checkCredentialLog(fd int, path, procInfo string) {
	if !fm.underDocRoot(path) {
		return
	}

	// Exclude known config file paths - these legitimately contain email-like patterns.
	if strings.HasPrefix(path, "/etc/") {
		return
	}
	for _, suffix := range []string{".conf", ".cfg", ".ini", ".yaml", ".yml"} {
		if strings.HasSuffix(path, suffix) {
			return
		}
	}

	data := readFromFd(fd, 4096)
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

	if credLines >= 5 {
		fm.sendAlertWithPath(alert.Critical, "credential_log_realtime",
			fmt.Sprintf("Harvested credential log detected: %s", path),
			fmt.Sprintf("%d credential lines (email:password format) found", credLines), path, procInfo)
	} else if emailCount >= 10 {
		fm.sendAlertWithPath(alert.High, "credential_log_realtime",
			fmt.Sprintf("Possible harvested email list: %s", path),
			fmt.Sprintf("%d email addresses found in %s", emailCount, filepath.Base(path)), path, procInfo)
	}
}

// checkPhishingZip checks if a newly created ZIP file matches known
// phishing-kit archive name patterns. The signal is the COMBINATION of a
// brand name and a phishing-suggestive token in the same filename --
// "office365-login.zip", "paypal-verify.zip", "microsoft-secure.zip".
// Plain plugin distribution backups (google-site-kit.zip, mailchimp.zip)
// have a brand without an action verb and don't fire.
func (fm *FileMonitor) checkPhishingZip(path, nameLower, procInfo string) {
	if !fm.underDocRoot(path) {
		return
	}

	// Brand impersonation targets: filenames mimicking a service users log in to.
	brands := []string{
		"office365", "office 365", "sharepoint", "onedrive",
		"microsoft", "outlook", "google", "gmail",
		"dropbox", "docusign", "adobe", "wetransfer",
		"paypal", "apple", "icloud", "netflix",
		"facebook", "instagram", "linkedin",
		"webmail", "roundcube", "cpanel",
	}
	// Phishing-suggestive verbs/nouns. These must co-occur with a brand
	// for the rule to fire. "kit" is intentionally NOT here -- many
	// official WordPress plugin slugs end in -kit (google-site-kit,
	// mailchimp-for-wp-kit) and were the dominant FP source.
	phishingIndicators := []string{
		"login", "signin", "sign-in", "sign_in",
		"verify", "verification",
		"secure", "security",
		"phish", "scam",
		"bank", "account",
		"capture", "harvest", "steal",
	}

	var matchedBrand string
	for _, b := range brands {
		if strings.Contains(nameLower, b) {
			matchedBrand = b
			break
		}
	}
	if matchedBrand == "" {
		return
	}
	var matchedIndicator string
	for _, p := range phishingIndicators {
		if strings.Contains(nameLower, p) {
			matchedIndicator = p
			break
		}
	}
	if matchedIndicator == "" {
		return
	}
	fm.sendAlertWithPath(alert.High, "phishing_kit_realtime",
		fmt.Sprintf("Suspected phishing kit archive uploaded: %s", path),
		fmt.Sprintf("Filename combines brand '%s' with phishing indicator '%s'", matchedBrand, matchedIndicator),
		path, procInfo)
}

// runSignatureScan runs YAML and YARA signature scanning on file content.
// Returns true if a match was found and an alert was sent.
// Non-critical YAML matches use directory-level dedup to avoid alert floods
// when a plugin directory has many files matching the same rule.
// Critical matches (backdoors, webshells) always alert per-file.
// scannedIdentity describes the object behind an event descriptor. Stat of the
// /proc magic link resolves the open file itself rather than walking the path
// again, so it still names the scanned inode after the path has been replaced.
// os.NewFile is avoided deliberately: its finalizer can close a descriptor the
// daemon still owns.
func scannedIdentity(fd int) os.FileInfo {
	info, err := os.Stat(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return nil
	}
	return info
}

func (fm *FileMonitor) runSignatureScan(data []byte, path, ext, procInfo string) bool {
	return fm.runSignatureScanWithSize(data, int64(len(data)), path, ext, procInfo, nil)
}

func (fm *FileMonitor) runEventSignatureScan(fd int, data []byte, path, ext, procInfo string) bool {
	return fm.runSignatureScanWithSize(data, int64(len(data)), path, ext, procInfo, scannedIdentity(fd))
}

func (fm *FileMonitor) runSignatureScanWithSize(data []byte, contentSize int64, path, ext, procInfo string, scanned os.FileInfo) bool {
	// Both engines see every file. A .yml hit used to end the scan here, so
	// a file matching a High .yml rule never met the Critical YARA rule and
	// the inline quarantine that only a Critical match triggers. Only a file
	// the .yml path already moved to quarantine is not handed to YARA.
	matched := false
	if scanner := signatures.Global(); scanner != nil {
		matches := scanner.ScanContentWithSize(data, ext, contentSize)
		if len(matches) > 0 {
			matched = true
			m := matches[0]
			sev := alert.High
			if m.Severity == "critical" {
				sev = alert.Critical
			}
			// Non-critical: dedup by rule+directory so 30 files in the same
			// plugin matching the same rule produce one alert, not 30.
			// Critical matches always alert per-file (real path for quarantine).
			suppressed := false
			if sev != alert.Critical {
				dirKey := m.RuleName + ":" + filepath.Dir(path)
				suppressed = !fm.shouldAlert("signature_match_realtime", dirKey)
			}
			if !suppressed {
				details := fmt.Sprintf("Category: %s\nDescription: %s\nMatched: %s",
					m.Category, m.Description, strings.Join(m.Matched, ", "))
				details += signatures.ReferencedPayloadDetail(data)
				finding := alert.Finding{
					Severity:    sev,
					Check:       "signature_match_realtime",
					Message:     fmt.Sprintf("Signature match [%s]: %s", m.RuleName, path),
					Details:     details,
					FilePath:    path,
					ProcessInfo: procInfo,
				}
				var qPath string
				var quarantined bool
				var paused *alert.Finding
				if sev == alert.Critical {
					// Capture provenance before remediation can remove the source.
					checks.StampContentFingerprint(&finding)
					qPath, quarantined, paused = checks.InlineQuarantineGatedIdentified(fm.currentCfg(), &finding, path, data, scanned)
				}
				// Publish after the inline decision so delivery sees its budget
				// provenance. A rejected window can still get full-file validation.
				fm.sendFileFinding(finding)
				if paused != nil && !alert.TryEnqueue(fm.alertCh, *paused) {
					atomic.AddInt64(&fm.droppedAlerts, 1)
				}
				if quarantined {
					fm.recordDropperQuarantine(path, qPath)
					fm.sendAlert(alert.Critical, "auto_response",
						fmt.Sprintf("AUTO-QUARANTINE (inline): %s moved to quarantine", path),
						fmt.Sprintf("Quarantined to: %s\nRule: %s", qPath, m.RuleName))
					return true
				}
			}
		}
	}

	if yaraScanner := yara.Active(); yaraScanner != nil {
		matches, err := yara.ScanBytesChecked(yaraScanner, path, data)
		if err != nil {
			fm.reportYARAScanError(path, err)
			return matched
		}
		if len(matches) > 0 {
			fm.sendAlertWithPath(alert.Critical, "yara_match_realtime",
				fmt.Sprintf("YARA rule match [%s]: %s", matches[0].RuleName, path),
				fmt.Sprintf("Matched %d YARA rule(s)", len(matches))+signatures.ReferencedPayloadDetail(data), path, procInfo)
			return true
		}
	}

	return matched
}

// stopping reports whether this monitor has been signalled to stop. A nil
// stopCh (a monitor built directly in a test) is never stopping, because a
// receive on a nil channel cannot proceed.
func (fm *FileMonitor) stopping() bool {
	select {
	case <-fm.stopCh:
		return true
	default:
		return false
	}
}

// reportYARAScanError names a changed file the scanner could not inspect.
// It is its own check rather than the deep scan's "yara_scan_incomplete",
// which reports scheduled coverage: that report fires for every archive past
// the scan size limit, roughly thirteen times a day forever on a live host,
// and sharing the name left a real scanning outage indistinguishable from
// routine backlog.
//
// Shutdown is not an outage. The daemon stops the YARA backend while this
// monitor's goroutine is still draining events, because the wait for workers
// comes after the teardown, so a clean restart otherwise reported a
// High-severity scanning failure every time. The teardown cannot move after
// that wait, which is unbounded and would hang on a wedged worker. The
// return happens before the rate-limit window is taken, so a suppressed
// shutdown report cannot swallow the first genuine failure afterwards.
func (fm *FileMonitor) reportYARAScanError(path string, err error) {
	if fm.stopping() {
		return
	}
	fm.yaraErrorReportMu.Lock()
	if !fm.lastYARAError.IsZero() && time.Since(fm.lastYARAError) < time.Minute {
		fm.yaraErrorReportMu.Unlock()
		return
	}
	fm.lastYARAError = time.Now()
	fm.yaraErrorReportMu.Unlock()
	fm.sendAlert(alert.High, "yara_realtime_scan_error",
		"YARA real-time scan could not inspect a changed file",
		fmt.Sprintf("File: %s\nError: %v", path, err))
}

// M7 - sendAlert uses droppedAlerts counter, separate from droppedEvents.
// No dedup - only used for system-level alerts (overflow reporting) that are
// already ticker-gated. File-related alerts should use sendAlertWithPath.
func (fm *FileMonitor) sendAlert(severity alert.Severity, check, message, details string) {
	finding := alert.Finding{
		Severity:  severity,
		Check:     check,
		Message:   message,
		Details:   details,
		Timestamp: time.Now(),
	}
	if !alert.TryEnqueue(fm.alertCh, finding) {
		atomic.AddInt64(&fm.droppedAlerts, 1)
	}
}

// sendAlertWithPath is like sendAlert but also sets the FilePath and
// ProcessInfo fields for structured propagation to auto-response.
// Applies per-path deduplication to prevent alert storms from rapid writes.
func (fm *FileMonitor) sendAlertWithPath(severity alert.Severity, check, message, details, filePath, processInfo string) {
	fm.sendFileFinding(alert.Finding{
		Severity:    severity,
		Check:       check,
		Message:     message,
		Details:     details,
		FilePath:    filePath,
		ProcessInfo: processInfo,
	})
}

func (fm *FileMonitor) sendFileFinding(finding alert.Finding) {
	dedupPath := finding.FilePath
	if finding.DedupKey != "" {
		// A later header or digest can change a staged finding's identity
		// within the path cooldown. Let persistent dedup see that evidence.
		dedupPath = finding.Key()
	}
	if !fm.shouldAlert(finding.Check, dedupPath) {
		return
	}
	finding.Timestamp = time.Now()
	checks.StampContentFingerprint(&finding)
	if !alert.TryEnqueue(fm.alertCh, finding) {
		atomic.AddInt64(&fm.droppedAlerts, 1)
	}
}

// shouldAlert returns true if this check+path combination hasn't been alerted
// recently. Prevents duplicate alerts from rapid writes to the same file.
// Uses LoadOrStore for atomic initial insertion to avoid TOCTOU races
// between concurrent analyzer workers.
func (fm *FileMonitor) shouldAlert(check, filePath string) bool {
	if filePath == "" {
		return true // no path = no dedup possible
	}
	key := check + ":" + filePath
	now := time.Now()
	if v, loaded := fm.alertDedup.LoadOrStore(key, now); loaded {
		if now.Sub(v.(time.Time)) < alertDedupTTL {
			return false
		}
		fm.alertDedup.Store(key, now) // refresh TTL on expiry
	}
	return true
}

// M7 - overflowReporter reports dropped events and alerts separately.
//
// Two timers feed this loop:
//   - 1-minute ticker: emits the periodic fanotify_overflow alert,
//     resets drop counters, runs reconcileDrops, and evicts stale alert
//     dedup entries.
//   - reconcileSig: out-of-cycle reconcile triggered by sendEvent when
//     sustained drops cross eagerReconcileDropThreshold within the
//     current tick. Closes the latency gap between a drop and its
//     reconcile read so the file's mtime is still inside reconcileWindow.
func (fm *FileMonitor) overflowReporter() {
	defer fm.wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-fm.stopCh:
			return
		case <-fm.reconcileSig:
			// Eager reconcile: do not reset counters, do not emit the
			// minute-tick alert. Just walk the tracked dirs and surface
			// any interesting file inside reconcileWindow. The minute
			// tick will still fire its alert + drain the counters when
			// it arrives.
			fm.reconcileDrops()
		case <-ticker.C:
			droppedEv := atomic.SwapInt64(&fm.droppedEvents, 0)
			droppedAl := atomic.SwapInt64(&fm.droppedAlerts, 0)
			if droppedEv > 0 {
				fm.sendAlert(alert.Warning, "fanotify_overflow",
					fmt.Sprintf("fanotify event queue overflowed: %d events dropped in last minute", droppedEv),
					"Possible event storm (backup, bulk update) or high-volume attack")
				// Recover coverage: scan files in directories that saw drops
				// so a threat landing during the storm is still detected.
				fm.reconcileDrops()
			}
			if droppedAl > 0 {
				fmt.Fprintf(os.Stderr, "[%s] alert channel full: %d alerts dropped in last minute\n", ts(), droppedAl)
			}
			// Evict stale dedup entries every minute
			now := time.Now()
			fm.alertDedup.Range(func(key, value any) bool {
				if now.Sub(value.(time.Time)) > alertDedupTTL {
					fm.alertDedup.Delete(key)
				}
				return true
			})
			evictStaleWPPathStatCache(now)
		}
	}
}

// evictStaleWPPathStatCache bounds the package-level WordPress path stat cache.
// The compare-delete keeps the minute sweep from removing a fresh stat result
// stored by an analyzer worker after Range observed an older entry.
func evictStaleWPPathStatCache(now time.Time) {
	cutoff := 2 * wpPathCacheTTL
	wpPathStatCache.Range(func(key, value any) bool {
		entry, ok := value.(wpPathCacheEntry)
		if !ok {
			wpPathStatCache.Delete(key)
			return true
		}
		if now.Sub(entry.ts) > cutoff {
			wpPathStatCache.CompareAndDelete(key, entry)
		}
		return true
	})
}

// isPHPExtension returns true for all PHP file extensions that can execute code.
// containsFunc checks if content contains a function call that isn't part of
// a longer identifier. Prevents "WP_Filesystem(" matching "exec(" or
// "preg_match(" matching "exec(". Checks the character before the match
// is not a letter, digit, or underscore.
func containsFunc(content, funcCall string) bool {
	idx := 0
	for {
		pos := strings.Index(content[idx:], funcCall)
		if pos < 0 {
			return false
		}
		absPos := idx + pos
		if absPos == 0 {
			return true
		}
		prev := content[absPos-1]
		if (prev < 'a' || prev > 'z') && (prev < 'A' || prev > 'Z') &&
			(prev < '0' || prev > '9') && prev != '_' {
			return true
		}
		idx = absPos + len(funcCall)
		if idx >= len(content) {
			return false
		}
	}
}

func isPHPExtension(nameLower string) bool {
	// Single source of truth shared with the periodic content scanners and the
	// rule engines so no path drifts on which extensions execute PHP.
	return contenttype.IsExecutablePHPName(nameLower)
}

func isPHPSourceExtension(nameLower string) bool {
	return contenttype.IsPHPSourceName(nameLower)
}

func isCGIExtension(nameLower string) bool {
	return strings.HasSuffix(nameLower, ".pl") ||
		strings.HasSuffix(nameLower, ".cgi") ||
		strings.HasSuffix(nameLower, ".py") ||
		strings.HasSuffix(nameLower, ".sh") ||
		strings.HasSuffix(nameLower, ".rb")
}

// checkCGIBackdoor reads a CGI script and checks for backdoor patterns.
// Detects Perl/Python/Bash backdoors like the LEVIATHAN toolkit.
func (fm *FileMonitor) checkCGIBackdoor(fd int, path, procInfo string) {
	recordReadTruncation(fd, 32768, "cgi_backdoor")
	data := readFromFd(fd, 32768)
	if data == nil {
		return
	}
	content := strings.ToLower(string(data))

	// Backdoor indicators in CGI scripts
	indicators := 0
	var matched []string

	// Indicators weighted by suspicion level. Generic patterns like
	// "request_method" and "cmd" removed — they match every CGI script.
	shellPatterns := []struct {
		pattern string
		desc    string
	}{
		{"system(", "system() call"},
		{"os.popen", "os.popen() call"},
		{"`$", "backtick execution with variable"},
		{"content_length", "reads POST body length"},
		{"base64_decode", "base64 decoding"},
		{"$_post", "PHP POST input"},
		{"$_get", "PHP GET input"},
		{"param(", "CGI parameter read"},
		{"qs.parse", "query string parsing"},
	}

	for _, sp := range shellPatterns {
		if strings.Contains(content, sp.pattern) {
			indicators++
			matched = append(matched, sp.desc)
		}
	}

	// 4+ indicators = likely backdoor
	if indicators >= 4 {
		fm.sendAlertWithPath(alert.Critical, "cgi_backdoor_realtime",
			fmt.Sprintf("CGI backdoor detected: %s", path),
			fmt.Sprintf("Indicators (%d): %s", indicators, strings.Join(matched, ", ")), path, procInfo)
		return
	}

	// CGI scripts in unusual locations (images, css, js directories)
	if strings.Contains(path, "/img/") || strings.Contains(path, "/images/") ||
		strings.Contains(path, "/css/") || strings.Contains(path, "/js/") ||
		strings.Contains(path, "/fonts/") || strings.Contains(path, "/icons/") {
		fm.sendAlertWithPath(alert.High, "cgi_suspicious_location_realtime",
			fmt.Sprintf("CGI script in non-CGI directory: %s", path),
			"Scripts should not exist in image/css/js directories", path, procInfo)
		return
	}

	// Run signature scan on the content
	fm.runEventSignatureScan(fd, data, path, filepath.Ext(path), procInfo)
}

// matchSuppression checks if a file path matches a suppression glob pattern.
// Supports patterns like "*/cache/*", "*/vendor/*", "*.log".
func matchSuppression(pattern, path string) bool {
	if pattern == "" {
		return false
	}
	// Direct match against full path
	if m, _ := filepath.Match(pattern, path); m {
		return true
	}
	// Match against basename (e.g. "*.log")
	if m, _ := filepath.Match(pattern, filepath.Base(path)); m {
		return true
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return strings.Contains(path, pattern)
	}
	if strings.ContainsAny(pattern, "?[") || !hasLeadingAnyDepthSuppressionGlob(pattern) {
		return false
	}
	residue := strings.ReplaceAll(pattern, "*", "")
	if strings.Contains(residue, "/") && strings.Trim(residue, "/") != "" {
		return strings.Contains(path, residue)
	}
	return false
}

func hasLeadingAnyDepthSuppressionGlob(pattern string) bool {
	firstSlash := strings.Index(pattern, "/")
	if firstSlash <= 0 {
		return false
	}
	return strings.Trim(pattern[:firstSlash], "*") == ""
}

// readHead opens a file by path and reads the first maxBytes.
// Kept for path-based checks (HTML phishing, credential logs, ZIP checks)
// that need os.Stat for file size anyway.
func readHead(path string, maxBytes int) []byte {
	if maxBytes <= 0 {
		return nil
	}
	// #nosec G304 -- readHead scans files surfaced by fanotify/scanner;
	// reading user files for signature analysis is the daemon's purpose.
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	// ReadAll over a LimitReader, not a single f.Read into a pre-sized
	// buffer: a short read would hand only a prefix to the detectors and
	// silently miss content deeper in the file.
	buf, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)))
	if err != nil || len(buf) == 0 {
		return nil
	}
	return buf
}

// looksLikePluginUpdate checks if a PHP file in uploads looks like a plugin
// update temp directory (e.g., elementor_t0q9y). Returns true if it matches
// the pattern of a known plugin extracting an update.
// M3 - uses sync.Map cache with 5-minute TTL for plugin directory stat results.
func looksLikePluginUpdate(path string) bool {
	// WordPress plugin updates extract to /uploads/{pluginname}_{random}/
	// Detect by extracting the directory name under uploads/ and checking
	// if a matching plugin exists in wp-content/plugins/.
	// No hardcoded whitelist - works for all 60,000+ WP plugins.
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

	// Strip the random suffix (e.g. "_7ocsd") - WordPress appends _XXXXX
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
	return cachedPathExists(wpRoot + "/wp-content/plugins/" + pluginName)
}

// cachedPathExists answers whether path exists, memoised for wpPathCacheTTL
// when it does and for wpPathNegativeTTL when it does not. The realtime path
// asks this once per file event during an update, so an uncached stat per
// staged file would be paid thousands of times per package; a missing path
// during an update is transient, so its answer must expire quickly.
func cachedPathExists(path string) bool {
	if cached, ok := wpPathStatCache.Load(path); ok {
		if entry, ok := cached.(wpPathCacheEntry); ok {
			ttl := wpPathCacheTTL
			if !entry.exists {
				ttl = wpPathNegativeTTL
			}
			if time.Since(entry.ts) < ttl {
				return entry.exists
			}
		}
	}

	_, err := os.Stat(path)
	exists := err == nil
	wpPathStatCache.Store(path, wpPathCacheEntry{
		exists: exists,
		ts:     time.Now(),
	})
	return exists
}
