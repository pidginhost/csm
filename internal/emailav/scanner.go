package emailav

import "time"

// Verdict is the result of scanning a single file.
type Verdict struct {
	Infected  bool
	Signature string
	Severity  string // "critical", "high", "warning"
}

// Scanner is the interface for an antivirus engine.
type Scanner interface {
	Name() string
	Scan(path string) (Verdict, error)
	Available() bool
}

// Finding records a single detection on a single file.
type Finding struct {
	Filename  string `json:"filename"`
	Engine    string `json:"engine"`
	Signature string `json:"signature"`
	Severity  string `json:"severity"`
}

// ScanResult aggregates the scan outcome for an entire email message.
type ScanResult struct {
	MessageID         string    `json:"message_id"`
	Infected          bool      `json:"infected"`
	Findings          []Finding `json:"findings"`
	ScannedAt         time.Time `json:"scanned_at"`
	EnginesUsed       []string  `json:"engines_used"`
	PartialExtraction bool      `json:"partial_extraction"`
	FailedEngines     []string  `json:"failed_engines,omitempty"`
	TimedOutEngines   []string  `json:"-"` // engines that timed out (for finding emission, not persisted)
	AllEnginesDown    bool      `json:"-"` // true if no engines were available
}
