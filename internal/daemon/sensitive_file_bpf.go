//go:build linux && bpf

package daemon

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	bpfprog "github.com/pidginhost/csm/internal/daemon/sensitive_file_bpfprog"
	csmlog "github.com/pidginhost/csm/internal/log"
)

type sensitiveFileBPF struct {
	objs    *bpfprog.SensitiveFileObjects
	link    link.Link
	reader  *bpf.Reader[SensitiveFileEvent]
	alertCh chan<- alert.Finding
	cfg     *config.Config
	count   atomic.Uint64

	// paths resolves a ringbuf event's dev+inode back to a watchset path.
	// digests tracks per-path content identity across refreshes; it is keyed
	// by path, not inode, because an atomic rewrite gives the same path a new
	// inode and that is a modification, not a new file.
	// liveReported collects exact file states whose LSM findings reached the
	// alert pipeline, so the digest diff suppresses only the same write.
	mu           sync.RWMutex
	paths        map[fileid]string
	digests      map[string]checks.SensitiveFileState
	liveReported map[string]checks.SensitiveFileState
}

type fileid struct {
	Dev uint64
	Ino uint64
}

func startSensitiveFileBPF(_ context.Context, alertCh chan<- alert.Finding, cfg *config.Config) (*sensitiveFileBPF, error) {
	caps := bpf.Probe()
	if !caps.LSMAttach || !caps.Ringbuf {
		return nil, bpf.ErrUnsupported
	}

	objs := &bpfprog.SensitiveFileObjects{}
	if err := bpfprog.LoadSensitiveFileObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	l, err := link.AttachLSM(link.LSMOptions{Program: objs.CsmFilePerm})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach lsm/file_permission: %w", err)
	}

	reader, err := bpf.NewReader[SensitiveFileEvent](objs.Events, decodeSensitiveFileEvent)
	if err != nil {
		_ = l.Close()
		objs.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	s := &sensitiveFileBPF{
		objs:         objs,
		link:         l,
		reader:       reader,
		alertCh:      alertCh,
		cfg:          cfg,
		paths:        map[fileid]string{},
		digests:      map[string]checks.SensitiveFileState{},
		liveReported: map[string]checks.SensitiveFileState{},
	}
	if err := s.refreshWatchset(false); err != nil {
		_ = s.link.Close()
		s.objs.Close()
		return nil, fmt.Errorf("populate watchset: %w", err)
	}
	return s, nil
}

func (s *sensitiveFileBPF) refreshWatchset(reportNew bool) error {
	next := make(map[fileid]string)
	var present []string
	for _, p := range checks.ExpandWatchset("/") {
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			continue
		}
		id := fileid{Dev: uint64(st.Dev), Ino: st.Ino}
		next[id] = p
		present = append(present, p)
	}

	for id := range next {
		key := bpfprog.SensitiveFileFileid{Dev: id.Dev, Ino: id.Ino}
		one := uint32(1)
		if err := s.objs.Watched.Update(&key, &one, 0); err != nil {
			return fmt.Errorf("update watched map: %w", err)
		}
	}

	// Hashing reads every watchset file, so it happens outside the lock. Only
	// this method writes s.digests, and its only callers are the startup path and
	// Run's select loop. Refreshes therefore cannot overlap, and
	// NextSensitiveDigests never mutates the captured map.
	s.mu.RLock()
	prevDigests := s.digests
	s.mu.RUnlock()

	digests, contents := checks.NextSensitiveDigests(prevDigests, present)

	// Run handles BPF events and refresh ticks in the same select loop, so no
	// event handler can update this set during the hashing pass. Snapshot after
	// hashing to keep that sequencing explicit.
	s.mu.Lock()
	liveReported := s.liveReported
	s.liveReported = map[string]checks.SensitiveFileState{}
	s.mu.Unlock()

	var newFindings []alert.Finding
	if reportNew {
		newFindings = checks.DiffSensitiveWatchset(prevDigests, digests, contents, liveReported)
	}
	for _, f := range newFindings {
		if s.emitFinding(f) {
			continue
		}
		// Do not absorb a finding that never reached the alert pipeline. Keeping
		// the old state makes the next refresh retry it.
		if prev, ok := prevDigests[f.FilePath]; ok {
			digests[f.FilePath] = prev
		} else {
			delete(digests, f.FilePath)
		}
	}

	s.mu.Lock()
	for id := range s.paths {
		if _, ok := next[id]; !ok {
			key := bpfprog.SensitiveFileFileid{Dev: id.Dev, Ino: id.Ino}
			_ = s.objs.Watched.Delete(&key)
		}
	}
	s.paths = next
	s.digests = digests
	s.mu.Unlock()
	return nil
}

func (s *sensitiveFileBPF) Mode() string       { return "bpf" }
func (s *sensitiveFileBPF) EventCount() uint64 { return s.count.Load() }

func (s *sensitiveFileBPF) Run(ctx context.Context) {
	defer func() {
		_ = s.reader.Close()
		_ = s.link.Close()
		s.objs.Close()
	}()

	go s.reader.Run(ctx)
	errorsCh := s.reader.Errors()
	eventsCh := s.reader.Events()

	refresh := time.NewTicker(s.refreshInterval())
	defer refresh.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-errorsCh:
			if !ok {
				errorsCh = nil
				continue
			}
			emitBPFReaderError(s.alertCh, "sensitive-file", err)
		case <-refresh.C:
			if err := s.refreshWatchset(true); err != nil {
				csmlog.Warn("sensitive_file bpf: watchset refresh failed", "err", err)
			}
		case ev, ok := <-eventsCh:
			if !ok {
				return
			}
			s.count.Add(1)
			eventID := fileid{Dev: ev.Dev, Ino: ev.Ino}
			s.mu.RLock()
			path := s.paths[eventID]
			s.mu.RUnlock()
			if path == "" {
				// Inode was just unwatched; skip rather than emit a path-less finding.
				continue
			}
			matchesBefore := sensitivePathMatchesFileID(path, eventID)
			state, contents := checks.NextSensitiveDigests(nil, []string{path})
			matchesAfter := sensitivePathMatchesFileID(path, eventID)
			content, contentKnown := contents[path]
			stableEventPath := matchesBefore && matchesAfter
			if !stableEventPath {
				// The event belongs to an inode that is no longer at this path.
				// Evaluate without content-based suppression, and do not let
				// replacement bytes suppress the path-based refresh finding.
				content = nil
				contentKnown = false
			}
			finding, emit := checks.EvaluateSensitiveFileWriteSnapshot(path, ev.UID, ev.PID, ev.Comm, content, contentKnown)
			if !emit {
				continue
			}
			if !s.emitFinding(finding) {
				continue
			}
			reportedState := state[path]
			if !stableEventPath || reportedState.ContentDigest == "" || reportedState.PathIdentity == "" {
				continue
			}
			s.mu.Lock()
			s.liveReported[path] = reportedState
			s.mu.Unlock()
		}
	}
}

func sensitivePathMatchesFileID(path string, want fileid) bool {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return false
	}
	return fileid{Dev: uint64(st.Dev), Ino: st.Ino} == want
}

func (s *sensitiveFileBPF) emitFinding(f alert.Finding) bool {
	select {
	case s.alertCh <- f:
		return true
	default:
		csmlog.Warn("sensitive_file bpf: alert channel full, dropping finding")
		return false
	}
}

func (s *sensitiveFileBPF) refreshInterval() time.Duration {
	if d := s.cfg.Detection.SensitiveFilesPollInterval; d > 0 {
		return d
	}
	return 5 * time.Minute
}
