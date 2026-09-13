package alert

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// Audit-log dispatching is layered on top of the existing email +
// webhook fork in Dispatch(). Sinks live behind a package-level
// manager so the daemon's per-call Dispatch path does not pay the
// cost of opening a JSONL file or dialling syslog on every alert.
//
// The manager keys its sink set by a fingerprint of the relevant
// config sub-block; on hot reload the fingerprint changes and the
// manager closes the old sinks and rebuilds.

var (
	auditMu             sync.Mutex
	auditSinks          []*managedAuditSink
	auditFingerprint    string
	auditNow            = time.Now
	openJSONLAuditSink  = func(path string) (AuditSink, error) { return NewJSONLSink(path) }
	openSyslogAuditSink = func(cfg SyslogConfig) (AuditSink, error) { return NewSyslogSink(cfg) }
)

type managedAuditSink struct {
	name       string
	open       func() (AuditSink, error)
	sink       AuditSink
	retryAt    time.Time
	retryDelay time.Duration
	failed     bool
	// Keep successful observation IDs across batches and transient sink
	// failures. Each destination owns its receipts so a failed destination
	// can receive a replay without duplicating the healthy destination.
	delivered map[[sha256.Size]byte]*list.Element
	recent    list.List
}

// Bound replay receipts independently of traffic volume. Evicted observations
// can be emitted again; distinct observations are never dropped by this cache.
const auditReceiptCap = 16384

func (s *managedAuditSink) remember(id [sha256.Size]byte) {
	if s.delivered == nil {
		s.delivered = make(map[[sha256.Size]byte]*list.Element)
	}
	if s.recent.Len() == auditReceiptCap {
		oldest := s.recent.Back()
		delete(s.delivered, oldest.Value.([sha256.Size]byte))
		s.recent.Remove(oldest)
	}
	s.delivered[id] = s.recent.PushFront(id)
}

// auditObservationKey distinguishes original evidence that the legacy action
// ID omits. For example, a process scan can report several PIDs with the same
// message and timestamp. Keep action IDs stable and hash scalar source evidence
// before redaction, without retaining its raw text or mutable enrichment.
func auditObservationKey(f Finding) [sha256.Size]byte {
	var data []byte
	for _, field := range []string{
		f.Timestamp.UTC().Format(time.RFC3339Nano), f.Check, f.Severity.String(),
		f.Message, f.FilePath, f.Details, strconv.Itoa(f.PID), f.SourceIP,
		f.TenantID, f.Domain, f.Mailbox, f.DedupKey, f.CoverageScope,
	} {
		// Quote preserves boundaries and invalid UTF-8 from raw log input.
		data = strconv.AppendQuote(data, field)
	}
	return sha256.Sum256(data)
}

// emitAudit records findings before email/webhook throttling. The manager lock
// covers the whole batch, including reconfiguration, so Close cannot invalidate
// a sink held by another dispatcher. Observers run outside the lock because
// they can dispatch findings themselves.
func emitAudit(cfg *config.Config, findings []Finding) {
	emitAuditWithSources(cfg, findings, nil)
}

func emitAuditWithSources(cfg *config.Config, findings, sources []Finding) {
	if cfg == nil {
		return
	}
	for _, f := range findings {
		notifyFindingObservers(f)
	}
	if len(sources) > 0 {
		// Notification dedup uses condition keys. Audit joins need every
		// distinct observation, including repeats with a new timestamp.
		combined := make([]Finding, 0, len(sources)+len(findings))
		seen := make(map[[sha256.Size]byte]bool, len(sources)+len(findings))
		for _, batch := range [][]Finding{sources, findings} {
			for _, f := range batch {
				id := auditObservationKey(f)
				if !seen[id] {
					seen[id] = true
					combined = append(combined, f)
				}
			}
		}
		findings = combined
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	ensureAuditSinksLocked(cfg)
	for _, f := range findings {
		ev := NewAuditEvent(cfg.Hostname, f)
		id := auditObservationKey(f)
		for _, s := range auditSinks {
			if receipt, delivered := s.delivered[id]; delivered {
				// Retained findings can be replayed every scan amid realtime
				// churn. Keep their receipts hot without growing the cache.
				s.recent.MoveToFront(receipt)
				continue
			}
			if s.sink == nil {
				auditEventsDropped.With(s.name).Inc()
				continue
			}
			if err := s.sink.Emit(ev); err != nil {
				auditEventsDropped.With(s.name).Inc()
				_ = s.sink.Close()
				s.sink = nil
				s.fail("emit", err)
			} else {
				s.retryDelay = 0
				s.remember(id)
			}
		}
	}
}

func ensureAuditSinks(cfg *config.Config) {
	auditMu.Lock()
	defer auditMu.Unlock()
	ensureAuditSinksLocked(cfg)
}

func ensureAuditSinksLocked(cfg *config.Config) {
	fp := auditConfigFingerprint(cfg)
	if fp != auditFingerprint {
		closeAuditSinksLocked()
		if cfg.Alerts.AuditLog.File.Enabled {
			path := cfg.Alerts.AuditLog.File.Path
			auditSinks = append(auditSinks, &managedAuditSink{name: "jsonl", open: func() (AuditSink, error) { return openJSONLAuditSink(path) }})
		}
		if cfg.Alerts.AuditLog.Syslog.Enabled {
			sc := SyslogConfig{
				Network:   cfg.Alerts.AuditLog.Syslog.Network,
				Address:   cfg.Alerts.AuditLog.Syslog.Address,
				Facility:  cfg.Alerts.AuditLog.Syslog.Facility,
				Hostname:  cfg.Hostname,
				TLSCAFile: cfg.Alerts.AuditLog.Syslog.TLSCAFile,
			}
			auditSinks = append(auditSinks, &managedAuditSink{name: "syslog", open: func() (AuditSink, error) { return openSyslogAuditSink(sc) }})
		}
		auditFingerprint = fp
	}
	for _, s := range auditSinks {
		if s.sink != nil || auditNow().Before(s.retryAt) {
			continue
		}
		sink, err := s.open()
		if err != nil {
			s.fail("init", err)
			continue
		}
		s.sink = sink
		auditSinkDegraded.With(s.name).Set(0)
		if s.failed {
			fmt.Fprintf(os.Stderr, "[audit-log] %s recovered\n", s.name)
		}
		s.failed = false
	}
}

func (s *managedAuditSink) fail(phase string, err error) {
	if s.retryDelay == 0 {
		s.retryDelay = time.Second
	} else {
		s.retryDelay = min(2*s.retryDelay, time.Minute)
	}
	s.retryAt = auditNow().Add(s.retryDelay)
	s.failed = true
	auditSinkDegraded.With(s.name).Set(1)
	fmt.Fprintf(os.Stderr, "[audit-log] %s %s failed; retry after %s: %v\n", s.name, phase, s.retryDelay, err)
}

// auditConfigFingerprint reduces the audit-log sub-block to a stable
// hash so ensureAuditSinks can detect config changes without a deep
// reflect-based diff. Hostname is included because it appears in
// every emitted event.
func auditConfigFingerprint(cfg *config.Config) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "host=%s|", cfg.Hostname)
	_, _ = fmt.Fprintf(h, "file.enabled=%t|file.path=%s|",
		cfg.Alerts.AuditLog.File.Enabled,
		cfg.Alerts.AuditLog.File.Path,
	)
	_, _ = fmt.Fprintf(h, "syslog.enabled=%t|syslog.network=%s|syslog.address=%s|syslog.facility=%s|syslog.tls=%s",
		cfg.Alerts.AuditLog.Syslog.Enabled,
		cfg.Alerts.AuditLog.Syslog.Network,
		cfg.Alerts.AuditLog.Syslog.Address,
		cfg.Alerts.AuditLog.Syslog.Facility,
		cfg.Alerts.AuditLog.Syslog.TLSCAFile,
	)
	return hex.EncodeToString(h.Sum(nil))
}

// CloseAuditSinks waits for in-flight emissions and releases active sinks.
// A later dispatch can initialize them again.
func CloseAuditSinks() {
	auditMu.Lock()
	defer auditMu.Unlock()
	closeAuditSinksLocked()
}

func closeAuditSinksLocked() {
	for _, s := range auditSinks {
		if s.sink != nil {
			_ = s.sink.Close()
		}
		auditSinkDegraded.With(s.name).Set(0)
	}
	auditSinks = nil
	auditFingerprint = ""
}

// resetAuditSinksForTest is the test-only seam to wipe the package
// state between cases. Production code never needs this -- live
// daemons run a single Dispatch path with a single config object.
func resetAuditSinksForTest() {
	CloseAuditSinks()
}

// findingObservers registry. Used by the daemon to feed the incident
// correlator without making the alert package depend on internal/incident.
var (
	findingObserversMu sync.RWMutex
	findingObservers   []findingObserver
	findingObserverSeq atomic.Uint64
)

type findingObserver struct {
	id uint64
	fn func(Finding)
}

// RegisterFindingObserver registers fn to be called for every finding
// dispatched through emitAudit. Returns a cancel func that removes the
// observer. Safe for concurrent use; observer panics are recovered so
// one bad observer cannot stop dispatch.
func RegisterFindingObserver(fn func(Finding)) func() {
	id := findingObserverSeq.Add(1)
	findingObserversMu.Lock()
	findingObservers = append(findingObservers, findingObserver{id: id, fn: fn})
	findingObserversMu.Unlock()
	return func() {
		findingObserversMu.Lock()
		defer findingObserversMu.Unlock()
		out := findingObservers[:0]
		for _, o := range findingObservers {
			if o.id != id {
				out = append(out, o)
			}
		}
		findingObservers = out
	}
}

// notifyFindingObservers fans a finding out to every registered observer.
// Each observer runs in a recover scope so a panic in one cannot stop
// dispatch to the rest, the audit-log sinks, or future ones.
func notifyFindingObservers(f Finding) {
	findingObserversMu.RLock()
	obs := append([]findingObserver(nil), findingObservers...)
	findingObserversMu.RUnlock()
	for _, o := range obs {
		func(o findingObserver) {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr,
						"alert: finding observer id=%d panic for check=%q: %s\n%s",
						o.id, f.Check, formatRecoverValue(r), debug.Stack())
				}
			}()
			o.fn(f)
		}(o)
	}
}

func formatRecoverValue(v any) (out string) {
	defer func() {
		if recover() != nil {
			out = strconv.Quote(fmt.Sprintf("<unprintable panic value of type %T>", v))
		}
	}()
	return strconv.QuoteToASCII(fmt.Sprint(v))
}
