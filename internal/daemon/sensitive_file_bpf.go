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

	mu    sync.RWMutex
	paths map[fileid]string
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
		objs:    objs,
		link:    l,
		reader:  reader,
		alertCh: alertCh,
		cfg:     cfg,
		paths:   map[fileid]string{},
	}
	if err := s.refreshWatchset(false); err != nil {
		_ = s.link.Close()
		s.objs.Close()
		return nil, fmt.Errorf("populate watchset: %w", err)
	}
	return s, nil
}

func (s *sensitiveFileBPF) refreshWatchset(reportNew bool) error {
	paths := checks.ExpandWatchset("/")
	next := make(map[fileid]string, len(paths))
	for _, p := range paths {
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			continue
		}
		id := fileid{Dev: uint64(st.Dev), Ino: st.Ino}
		next[id] = p
	}

	for id := range next {
		key := bpfprog.SensitiveFileFileid{Dev: id.Dev, Ino: id.Ino}
		one := uint32(1)
		if err := s.objs.Watched.Update(&key, &one, 0); err != nil {
			return fmt.Errorf("update watched map: %w", err)
		}
	}
	var newFindings []alert.Finding
	s.mu.Lock()
	if reportNew {
		for id, path := range next {
			if _, ok := s.paths[id]; ok {
				continue
			}
			if f, emit := checks.EvaluateSensitiveFileAppearance(path); emit {
				newFindings = append(newFindings, f)
			}
		}
	}
	for id := range s.paths {
		if _, ok := next[id]; !ok {
			key := bpfprog.SensitiveFileFileid{Dev: id.Dev, Ino: id.Ino}
			_ = s.objs.Watched.Delete(&key)
		}
	}
	s.paths = next
	s.mu.Unlock()
	for _, f := range newFindings {
		s.emitFinding(f)
	}
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

	refresh := time.NewTicker(s.refreshInterval())
	defer refresh.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-refresh.C:
			if err := s.refreshWatchset(true); err != nil {
				csmlog.Warn("sensitive_file bpf: watchset refresh failed", "err", err)
			}
		case ev, ok := <-s.reader.Events():
			if !ok {
				return
			}
			s.count.Add(1)
			s.mu.RLock()
			path := s.paths[fileid{Dev: ev.Dev, Ino: ev.Ino}]
			s.mu.RUnlock()
			if path == "" {
				// Inode was just unwatched; skip rather than emit a path-less finding.
				continue
			}
			finding, emit := checks.EvaluateSensitiveFileWrite(path, ev.UID, ev.PID, ev.Comm)
			if !emit {
				continue
			}
			s.emitFinding(finding)
		}
	}
}

func (s *sensitiveFileBPF) emitFinding(f alert.Finding) {
	select {
	case s.alertCh <- f:
	default:
		csmlog.Warn("sensitive_file bpf: alert channel full, dropping finding")
	}
}

func (s *sensitiveFileBPF) refreshInterval() time.Duration {
	if d := s.cfg.Detection.SensitiveFilesPollInterval; d > 0 {
		return d
	}
	return 5 * time.Minute
}
