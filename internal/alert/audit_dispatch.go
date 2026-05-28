package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"

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
	auditMu          sync.Mutex
	auditSinks       []AuditSink
	auditFingerprint string
)

// emitAudit ships every finding through every configured audit-log
// sink. Called from Dispatch BEFORE rate-limit checks so the audit
// trail is complete even when email/webhook are throttled.
func emitAudit(cfg *config.Config, findings []Finding) {
	if cfg == nil {
		return
	}
	ensureAuditSinks(cfg)

	auditMu.Lock()
	sinks := append([]AuditSink(nil), auditSinks...)
	auditMu.Unlock()

	for _, f := range findings {
		// Observer fan-out runs first so the incident correlator sees
		// every finding even when no audit sinks are configured.
		notifyFindingObservers(f)
		if len(sinks) == 0 {
			continue
		}
		ev := NewAuditEvent(cfg.Hostname, f)
		for _, s := range sinks {
			if err := s.Emit(ev); err != nil {
				fmt.Fprintf(os.Stderr, "[audit-log] %s emit failed: %v\n", s.Name(), err)
			}
		}
	}
}

// ensureAuditSinks (re)builds the active sink set when the relevant
// config sub-block has changed since the last build. On the
// happy-path steady state this is a fingerprint compare and a return.
func ensureAuditSinks(cfg *config.Config) {
	fp := auditConfigFingerprint(cfg)
	auditMu.Lock()
	defer auditMu.Unlock()
	if fp == auditFingerprint && auditSinks != nil {
		return
	}
	// Config changed -- shut down the old sinks before building new
	// ones so file descriptors / sockets are released cleanly.
	for _, s := range auditSinks {
		_ = s.Close()
	}
	auditSinks = nil

	if cfg.Alerts.AuditLog.File.Enabled && cfg.Alerts.AuditLog.File.Path != "" {
		s, err := NewJSONLSink(cfg.Alerts.AuditLog.File.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[audit-log] jsonl init failed: %v\n", err)
		} else {
			auditSinks = append(auditSinks, s)
		}
	}
	if cfg.Alerts.AuditLog.Syslog.Enabled {
		s, err := NewSyslogSink(SyslogConfig{
			Network:   cfg.Alerts.AuditLog.Syslog.Network,
			Address:   cfg.Alerts.AuditLog.Syslog.Address,
			Facility:  cfg.Alerts.AuditLog.Syslog.Facility,
			Hostname:  cfg.Hostname,
			TLSCAFile: cfg.Alerts.AuditLog.Syslog.TLSCAFile,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[audit-log] syslog init failed: %v\n", err)
		} else {
			auditSinks = append(auditSinks, s)
		}
	}
	auditFingerprint = fp
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

// CloseAuditSinks shuts down every active sink. Called from the
// daemon at shutdown so file descriptors / sockets are released
// before the process exits. Safe to call when no sinks are open.
func CloseAuditSinks() {
	auditMu.Lock()
	defer auditMu.Unlock()
	for _, s := range auditSinks {
		_ = s.Close()
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
// dispatch to the rest, the audit-log sinks, or future ones. The
// recover value is logged with the observer id so a recurring panic
// (correlator nil deref, future plugin bug) leaves operator-visible
// trace instead of failing silently every dispatch tick.
func notifyFindingObservers(f Finding) {
	findingObserversMu.RLock()
	obs := append([]findingObserver(nil), findingObservers...)
	findingObserversMu.RUnlock()
	for _, o := range obs {
		func(o findingObserver) {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr,
						"alert: finding observer id=%d panic for check=%q: %v\n%s",
						o.id, f.Check, r, debug.Stack())
				}
			}()
			o.fn(f)
		}(o)
	}
}
