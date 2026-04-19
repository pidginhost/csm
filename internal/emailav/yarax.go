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
	backend yara.Backend
}

// NewYaraXScanner returns a scanner backed by b. Pass yara.Active() so
// the adapter follows whatever backend the daemon installed at startup.
// A nil backend produces an unavailable scanner (Available() == false);
// callers must still construct the scanner so the orchestrator's
// engine list has a stable shape regardless of backend state.
func NewYaraXScanner(b yara.Backend) *YaraXScanner {
	return &YaraXScanner{backend: b}
}

func (s *YaraXScanner) Name() string { return "yara-x" }

// Available reports whether the backend has rules compiled. Under worker
// mode this is a liveness probe against the child process (Supervisor's
// RuleCount() round-trips via Ping); if the worker is down we report
// unavailable rather than silently returning clean verdicts on files we
// could not actually scan.
func (s *YaraXScanner) Available() bool {
	return s.backend != nil && s.backend.RuleCount() > 0
}

// Scan reads path and matches against the backend's compiled rules.
// Returns the first matching rule's verdict, with severity taken from
// the rule's "severity" metadata (defaulting to "high" when absent).
func (s *YaraXScanner) Scan(path string) (Verdict, error) {
	if s.backend == nil {
		return Verdict{}, fmt.Errorf("no YARA backend configured")
	}
	// #nosec G304 -- path is a quarantined attachment staged by the spool watcher under our own root.
	data, err := os.ReadFile(path)
	if err != nil {
		return Verdict{}, fmt.Errorf("reading file: %w", err)
	}
	matches := s.backend.ScanBytes(data)
	if len(matches) == 0 {
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
