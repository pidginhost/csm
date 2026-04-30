//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/emailspool"
)

// spoolWatcher watches /var/spool/exim/input for new -H files. cPanel hashes
// msgIDs into 64+ subdirs; the watcher enumerates them at start and watches
// IN_CREATE on the parent so subdirs that appear later are also picked up.
//
// On every IN_CLOSE_WRITE / IN_MOVED_TO whose name ends in "-H", the
// supplied callback is invoked synchronously with the absolute path. The
// callback must not block long; spawn worker goroutines if needed.
type spoolWatcher struct {
	root    string
	onFile  func(path string)
	fd      int
	parentW int
	mu      sync.Mutex
	subDirs map[int]string // watch descriptor -> path

	overflowCount uint64
	onOverflow    func() // invoked from Run() the moment IN_Q_OVERFLOW arrives
	metrics       *phpRelayMetrics
}

// SetOverflowHandler wires the recovery scan + Critical finding emission
// into the watcher. Caller passes a closure that calls runRecoveryScan
// against the spool root and emits findings via the daemon alerter.
func (w *spoolWatcher) SetOverflowHandler(fn func()) { w.onOverflow = fn }

// SetMetrics wires the phpRelayMetrics sink. Optional -- nil disables
// observation (used by tests). Must be called before Run; concurrent
// invocation after Run is not safe.
func (w *spoolWatcher) SetMetrics(m *phpRelayMetrics) { w.metrics = m }

func newSpoolWatcher(root string, onFile func(path string)) (*spoolWatcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify_init1: %w", err)
	}
	parentMask := uint32(unix.IN_CREATE | unix.IN_MOVED_TO)
	parentW, err := unix.InotifyAddWatch(fd, root, parentMask)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("inotify_add_watch %s: %w", root, err)
	}
	w := &spoolWatcher{
		root:    root,
		onFile:  onFile,
		fd:      fd,
		parentW: parentW,
		subDirs: make(map[int]string),
	}
	// Enumerate existing subdirs.
	entries, err := os.ReadDir(root)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("readdir %s: %w", root, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if err := w.addSubdir(filepath.Join(root, e.Name())); err != nil {
			// Non-fatal -- continue with what we have.
			continue
		}
	}
	return w, nil
}

func (w *spoolWatcher) addSubdir(path string) error {
	mask := uint32(unix.IN_CLOSE_WRITE | unix.IN_MOVED_TO)
	wd, err := unix.InotifyAddWatch(w.fd, path, mask)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.subDirs[wd] = path
	w.mu.Unlock()
	return nil
}

func (w *spoolWatcher) Close() error {
	if w.fd != 0 {
		return unix.Close(w.fd)
	}
	return nil
}

// Run drains inotify events until ctx is cancelled.
func (w *spoolWatcher) Run(ctx context.Context) {
	defer func() { _ = w.Close() }()
	buf := make([]byte, 16*1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := syscall.Read(w.fd, buf)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				// Briefly yield via select so cancellation is responsive.
				select {
				case <-ctx.Done():
					return
				default:
					// Use a small ppoll-equivalent: read again after the kernel buffers.
					var fdset unix.FdSet
					fdset.Bits[w.fd/64] |= 1 << uint(w.fd%64)
					ts := unix.Timespec{Sec: 0, Nsec: 100 * 1e6}
					_, _ = unix.Pselect(w.fd+1, &fdset, nil, nil, &ts, nil)
					continue
				}
			}
			// Treat other errors as fatal; supervisor will restart us.
			return
		}
		offset := 0
		for offset+unix.SizeofInotifyEvent <= n {
			// #nosec G103 -- bounds-checked above; standard inotify decode pattern.
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			nameBytes := buf[offset+unix.SizeofInotifyEvent : offset+unix.SizeofInotifyEvent+int(ev.Len)]
			name := strings.TrimRight(string(nameBytes), "\x00")
			offset += unix.SizeofInotifyEvent + int(ev.Len)

			if ev.Mask&unix.IN_Q_OVERFLOW != 0 {
				w.overflowCount++
				if w.metrics != nil {
					w.metrics.InotifyOverflows.Inc()
				}
				if w.onOverflow != nil {
					w.onOverflow()
				}
				continue
			}
			if int(ev.Wd) == w.parentW {
				if ev.Mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 && name != "" {
					full := filepath.Join(w.root, name)
					if fi, err := os.Stat(full); err == nil && fi.IsDir() {
						_ = w.addSubdir(full)
					}
				}
				continue
			}
			w.mu.Lock()
			dir, ok := w.subDirs[int(ev.Wd)]
			w.mu.Unlock()
			if !ok || name == "" {
				continue
			}
			if !strings.HasSuffix(name, "-H") {
				continue
			}
			w.onFile(filepath.Join(dir, name))
		}
	}
}

// OverflowCount returns the number of IN_Q_OVERFLOW events observed.
// Used by the daemon to drive recovery scans (Task I3).
//
//nolint:unused // consumed by daemon wiring (Task O2)
func (w *spoolWatcher) OverflowCount() uint64 {
	return w.overflowCount
}

// spoolPipeline ties together: parse headers -> compute signals -> update
// windows -> evaluate paths -> emit findings via alerter callback.
type spoolPipeline struct {
	eng        *evaluator
	domains    *userDomainsResolver
	policies   *emailspool.Policies
	msgIndex   *msgIDIndex
	ignores    *ignoreList
	alerter    func(alert.Finding)
	rebuilding atomic.Bool
}

func newSpoolPipeline(eng *evaluator, domains *userDomainsResolver, pol *emailspool.Policies, idx *msgIDIndex, ignores *ignoreList, alerter func(alert.Finding)) *spoolPipeline {
	eng.SetPolicies(pol)
	return &spoolPipeline{
		eng: eng, domains: domains, policies: pol, msgIndex: idx, ignores: ignores, alerter: alerter,
	}
}

// SetRebuilding gates finding emission during the startup spool-walker
// rebuild pass. When true: state is updated, findings are NOT emitted.
func (p *spoolPipeline) SetRebuilding(v bool) { p.rebuilding.Store(v) }

// OnFile is the inotify callback. Parses, signals, updates state, evaluates.
func (p *spoolPipeline) OnFile(path string) {
	h, err := emailspool.ParseHeaders(path)
	if err != nil {
		if p.eng != nil && p.eng.metrics != nil {
			p.eng.metrics.SpoolReadErrors.Inc()
		}
		return
	}
	if h.XPHPScript == "" {
		return
	}
	msgID := msgIDFromPath(path)
	if msgID == "" {
		return
	}
	if p.msgIndex != nil && p.msgIndex.Has(msgID) {
		return // queue-runner re-write dedup
	}

	auth, _ := p.domains.Domains(h.EnvelopeUser)
	sig := computeSignals(h, auth, p.policies)
	if sig.ScriptKey == "" {
		return
	}
	if p.ignores != nil && p.ignores.Has(sig.ScriptKey) {
		return
	}

	if p.msgIndex != nil {
		p.msgIndex.Put(msgID, indexEntry{
			ScriptKey: string(sig.ScriptKey),
			SourceIP:  sig.SourceIP,
			CPUser:    h.EnvelopeUser,
			At:        time.Now(),
		})
	}

	state := p.eng.scripts.getOrCreate(sig.ScriptKey)
	state.append(scriptEvent{
		At:               time.Now(),
		MsgID:            msgID,
		FromMismatch:     sig.FromMismatch,
		AdditionalSignal: sig.AdditionalSignal,
		SourceIP:         sig.SourceIP,
	})
	state.recordActive(msgID, time.Now())

	if p.policies == nil || !p.policies.IsProxyIP(sig.SourceIP) {
		p.eng.ips.append(sig.SourceIP, sig.ScriptKey, time.Now())
	}

	if p.rebuilding.Load() {
		return
	}
	findings := p.eng.evaluatePaths(sig.ScriptKey, sig.SourceIP, h.EnvelopeUser, time.Now())
	for _, f := range findings {
		p.alerter(f)
	}
}

// msgIDFromPath returns the msgID portion of a /path/<msgID>-H file.
func msgIDFromPath(path string) string {
	base := filepath.Base(path)
	if !strings.HasSuffix(base, "-H") {
		return ""
	}
	return strings.TrimSuffix(base, "-H")
}

// runRecoveryScan walks every -H file under spoolRoot/*/, sorts by mtime
// (oldest first), invokes onFile up to maxFiles. Returns the number scanned
// and whether the cap was hit.
//
//nolint:unused // consumed by daemon wiring (Task O2)
func runRecoveryScan(spoolRoot string, maxFiles int, onFile func(string)) (int, bool) {
	type entry struct {
		path string
		mod  time.Time
	}
	var entries []entry
	subs, err := os.ReadDir(spoolRoot)
	if err != nil {
		return 0, false
	}
	for _, sub := range subs {
		if !sub.IsDir() {
			continue
		}
		subPath := filepath.Join(spoolRoot, sub.Name())
		files, err := os.ReadDir(subPath)
		if err != nil {
			continue
		}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), "-H") {
				continue
			}
			full := filepath.Join(subPath, f.Name())
			fi, err := os.Stat(full)
			if err != nil {
				continue
			}
			entries = append(entries, entry{path: full, mod: fi.ModTime()})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].mod.Before(entries[j].mod) })
	truncated := false
	if len(entries) > maxFiles {
		entries = entries[:maxFiles]
		truncated = true
	}
	for _, e := range entries {
		onFile(e.path)
	}
	return len(entries), truncated
}

// runStartupSpoolWalker walks every currently-queued -H file through the
// pipeline in REBUILD mode, then performs one re-evaluation pass over the
// reconstructed scriptStates. Findings are emitted ONLY in the re-evaluation
// pass, so the rebuild itself never produces duplicate findings for the
// same in-queue mail.
func runStartupSpoolWalker(spoolRoot string, p *spoolPipeline) {
	p.SetRebuilding(true)
	subs, err := os.ReadDir(spoolRoot)
	if err == nil {
		for _, sub := range subs {
			if !sub.IsDir() {
				continue
			}
			subPath := filepath.Join(spoolRoot, sub.Name())
			files, err := os.ReadDir(subPath)
			if err != nil {
				continue
			}
			for _, f := range files {
				if !strings.HasSuffix(f.Name(), "-H") {
					continue
				}
				p.OnFile(filepath.Join(subPath, f.Name()))
			}
		}
	}
	p.SetRebuilding(false)

	// Re-evaluation pass.
	snap := p.eng.scripts.Snapshot()
	now := time.Now()
	for k, s := range snap {
		// We don't have per-script source IP in the snapshot; pass empty
		// sourceIP. Path 4 (HTTP-IP fanout) is keyed off perIPWindow which
		// was already populated in OnFile, so an empty SourceIP here just
		// means the per-script Path 4 finding doesn't carry an IP -- the
		// window itself still triggers correctly via direct OnFile calls
		// during normal operation.
		cpuser := ""
		// Best-effort cpuser: read it from any active msgID's index entry.
		if p.msgIndex != nil {
			if ids, _ := s.snapshotActiveMsgs(); len(ids) > 0 {
				if e, ok := p.msgIndex.Get(ids[0]); ok {
					cpuser = e.CPUser
				}
			}
		}
		for _, f := range p.eng.evaluatePaths(k, "", cpuser, now) {
			p.alerter(f)
		}
	}
}

// spoolSupervisor wraps a goroutine that may panic. After maxRestarts
// consecutive panics, it stops trying and invokes OnFailed (used to emit
// a Critical finding email_php_relay_watcher_failed).
type spoolSupervisor struct {
	fn          func(ctx context.Context)
	maxRestarts int
	OnFailed    func()
}

//nolint:unused // consumed by daemon wiring (Task O2)
func newSpoolSupervisor(fn func(ctx context.Context), maxRestarts int) *spoolSupervisor {
	return &spoolSupervisor{fn: fn, maxRestarts: maxRestarts, OnFailed: func() {}}
}

func (s *spoolSupervisor) Run(ctx context.Context) {
	backoff := 100 * time.Millisecond
	for attempt := 0; attempt <= s.maxRestarts; attempt++ {
		select {
		case <-ctx.Done():
			return
		default:
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					_ = r // Panic recovered; loop will sleep + retry.
				}
			}()
			s.fn(ctx)
		}()
		if ctx.Err() != nil {
			return
		}
		if attempt == s.maxRestarts {
			s.OnFailed()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}
