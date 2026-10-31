// Package yaraipc defines the protocol between the CSM daemon and `csm
// yara-worker`, which runs in locked-down transient units: a compile unit
// that turns rule text into compiled rules, and a scan unit that loads them
// and scans descriptors. Frames are workerproc frames on the unit's socket
// pair; rule text, compiled rules and scanned content all travel as
// descriptors, never inside a frame.
package yaraipc

// MaxFrameBytes caps a single request or response payload. Scanned bytes
// never travel in a frame: they come as a descriptor. The cap bounds what a
// confused or hostile peer can make the other side allocate.
const MaxFrameBytes = 16 << 20

// ProtocolVersion is the hello version of the worker protocol.
const ProtocolVersion = 1

// Ops of the worker. Strings, so a daemon and worker from different builds
// fail with a recognisable unknown-op error.
const (
	// OpCompile compiles the rule text passed as the request's one
	// descriptor, split by CompileArgs, and returns the compiled rules in a
	// sealed memfd.
	OpCompile = "compile"
	// OpLoad loads compiled rules from the request's one descriptor. A worker
	// answers ping and scan_fd only after a load.
	OpLoad = "load"
	// OpPing reports the loaded rule count.
	OpPing = "ping"
	// OpScanFD scans the file passed as the request's one descriptor, so
	// the worker never opens a path and nothing is copied through JSON.
	OpScanFD = "scan_fd"
)

// MaxSources caps the rule files one compile request may name.
const MaxSources = 1024

// MaxSerializedRules caps compiled rules in bytes. Forge full serializes to
// about 25 MB.
const MaxSerializedRules = 256 << 20

// SourceSpan names one rule file inside a compile request's descriptor: the
// files sit back to back, in order, Size bytes each.
type SourceSpan struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// CompileArgs lists the rule files in a compile request's descriptor.
type CompileArgs struct {
	Sources []SourceSpan `json:"sources"`
}

// CompileResult answers OpCompile. A rule that does not compile is a result,
// not a worker failure: CompileError is set and no descriptor comes back.
type CompileResult struct {
	RuleCount    int    `json:"rule_count"`
	CompileError string `json:"compile_error,omitempty"`
}

// LoadResult answers OpLoad and OpPing with the loaded rule count.
type LoadResult struct {
	RuleCount int `json:"rule_count"`
}

// ScanFDArgs bounds how much of the descriptor the worker reads. No name is
// sent: the archive-by-name skip is for files on disk and is decided in the
// daemon.
type ScanFDArgs struct {
	MaxBytes int `json:"max_bytes"`
}

// scanFDResult requires an explicit matches array, including for clean scans.
// An empty or unrelated worker reply must not stand in for a completed scan.
type scanFDResult struct {
	Matches []Match `json:"matches"`
}

// Match mirrors yara.Match but is part of this package's wire contract so the
// daemon does not need the engine to read a reply.
//
// Meta carries string-valued rule metadata (identifier -> value) pulled
// from yara_x `rule.Metadata()` inside the worker, where the compiled
// rules live. Non-string metadata (int / float / bool / bytes) is
// dropped: wiring only string values is a deliberate policy, not a
// fidelity claim. Consumers that need a specific key document their own
// default; e.g. emailav maps a missing "severity" entry to "high".
// Omitted from the wire when empty so the per-scan payload cost is zero
// for the common clean-file case.
type Match struct {
	RuleName string            `json:"rule"`
	Meta     map[string]string `json:"meta,omitempty"`
}
