//go:build yara

package emailav

import (
	"fmt"
	"os"

	"github.com/pidginhost/csm/internal/yara"
)

// defaultSeverity is emailav's fallback when a matching rule carries no
// "severity" metadata key. Matches the behaviour the old adapter had
// before IPC existed: we treat an unlabelled match as "high" rather
// than silently reclassifying it.
const defaultSeverity = "high"

// YaraXScanner is the emailav adapter over a yara.Backend. The backend
// can be the in-process *yara.Scanner (default) or the supervised
// out-of-process worker (when signatures.yara_worker_enabled is on);
// both expose matches with string metadata pulled from the rule's
// Metadata(), so this adapter is indifferent to which one is active.
type YaraXScanner struct {
	backend  yara.Backend
	resolver func() yara.Backend
}

// NewYaraXScanner returns a scanner backed by a fixed backend snapshot. A nil
// backend produces an unavailable scanner (Available() == false); callers must
// still construct the scanner so the orchestrator's engine list has a stable
// shape regardless of backend state. Use NewActiveYaraXScanner when the scanner
// should follow later yara.Active() swaps.
func NewYaraXScanner(b yara.Backend) *YaraXScanner {
	return &YaraXScanner{backend: b}
}

// NewActiveYaraXScanner follows the process-wide active YARA backend at scan
// time. This lets email AV recover when the daemon starts with the worker down
// and the backend is installed later by the boot-retry path.
func NewActiveYaraXScanner() *YaraXScanner {
	return &YaraXScanner{resolver: yara.Active}
}

func (s *YaraXScanner) Name() string { return "yara-x" }

func (s *YaraXScanner) currentBackend() yara.Backend {
	if s.resolver != nil {
		return s.resolver()
	}
	return s.backend
}

// Available reports whether the backend has rules compiled. Under worker
// mode this is a liveness probe against the child process (Supervisor's
// RuleCount() round-trips via Ping); if the worker is down we report
// unavailable rather than silently returning clean verdicts on files we
// could not actually scan.
func (s *YaraXScanner) Available() bool {
	backend := s.currentBackend()
	return backend != nil && backend.RuleCount() > 0
}

// Scan reads path and matches against the backend's compiled rules.
// Returns the first matching rule's verdict, with severity taken from
// the rule's "severity" metadata (defaulting to "high" when absent).
func (s *YaraXScanner) Scan(path string) (Verdict, error) {
	backend := s.currentBackend()
	if backend == nil {
		return Verdict{}, fmt.Errorf("no YARA backend configured")
	}
	// #nosec G304 -- path is a quarantined attachment staged by the spool watcher under our own root.
	data, err := os.ReadFile(path)
	if err != nil {
		return Verdict{}, fmt.Errorf("reading file: %w", err)
	}
	matches, err := yara.ScanBytesChecked(backend, data)
	if err != nil {
		// Fail closed: a scan that could not complete (worker down, the
		// attachment too large for one IPC frame, a transport error) must
		// not be reported as a clean file. The orchestrator records this as
		// an errored engine, not a clean verdict.
		return Verdict{}, fmt.Errorf("yara scan failed: %w", err)
	}
	if len(matches) == 0 {
		// Defence against silent fail-open: a healthy backend with zero
		// matches looks identical from outside to a backend whose
		// internal scan errored (rules.Scan() returns nil on failure).
		// If the backend was healthy when the orchestrator dispatched
		// this work but is no longer reporting any rules now, the worker
		// almost certainly crashed mid-scan; report an error so the
		// orchestrator routes the message conservatively instead of
		// shipping it as "clean".
		if backend.RuleCount() == 0 {
			return Verdict{}, fmt.Errorf("yara backend became unavailable during scan")
		}
		return Verdict{Infected: false}, nil
	}
	m := matches[0]
	severity := m.Meta["severity"]
	if severity == "" {
		severity = defaultSeverity
	}
	return Verdict{
		Infected:  true,
		Signature: m.RuleName,
		Severity:  severity,
	}, nil
}
