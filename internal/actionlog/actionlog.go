// Package actionlog records what CSM did to a host, as opposed to what it
// found. Findings already have one stream (the SIEM audit log); actions were
// spread across a firewall log, a web UI log, a mail-freeze log and, for
// everything the daemon did on its own, nothing at all.
//
// One record per action, one file, one schema. Each record names the
// privileged operation it belongs to (the IDs in internal/privops), so an
// operator can read the capability matrix and the action log with the same
// vocabulary, and carries the evidence that makes the action reviewable: the
// exact argv when CSM ran a command, and the file's digest before and after
// when it changed a file.
package actionlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SchemaVersion is bumped only on an incompatible change. Additive fields do
// not bump it, so a parser can pin on v and ignore unknown keys.
const SchemaVersion = 1

// Result is the outcome of an action.
type Result string

const (
	// Applied means the action changed the host.
	Applied Result = "applied"
	// DryRun means CSM decided to act and did not, because a dry-run or
	// observe setting was in force. The record says what it would have done.
	DryRun Result = "dry_run"
	// Failed means the action was attempted and did not complete.
	Failed Result = "failed"
	// Refused means a safety rule stopped the action before it ran.
	Refused Result = "refused"
)

// Actor is who started the action.
type Actor string

const (
	// Daemon means CSM acted on its own.
	Daemon Actor = "daemon"
	// CLI means an operator ran a command.
	CLI Actor = "cli"
	// WebUI means an operator used the dashboard or the API.
	WebUI Actor = "webui"
)

// FileState is a file's identity at one moment. Digest is a SHA-256 of the
// content; an empty digest with Exists false records a file that was not there.
type FileState struct {
	Exists bool   `json:"exists"`
	Digest string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Mode   string `json:"mode,omitempty"`
	UID    uint32 `json:"uid,omitempty"`
	GID    uint32 `json:"gid,omitempty"`
}

// Record is one action.
type Record struct {
	V         int       `json:"v"`
	Timestamp time.Time `json:"ts"`
	Hostname  string    `json:"hostname,omitempty"`
	// Op is the privileged-operation ID from internal/privops.
	Op string `json:"op"`
	// Actor and ActorDetail say who asked for it. ActorDetail carries the
	// operator's source address for a web UI action, or the command name for
	// a CLI action.
	Actor       Actor  `json:"actor"`
	ActorDetail string `json:"actor_detail,omitempty"`
	// FindingID ties the action to the finding that caused it, using the same
	// ID the SIEM audit log emits.
	FindingID string `json:"finding_id,omitempty"`
	// Target is what was acted on: a path, an address, a message ID.
	Target  string `json:"target"`
	Account string `json:"account,omitempty"`
	Reason  string `json:"reason,omitempty"`
	// Command is the exact argv when CSM ran a program. Empty when the action
	// was performed through system calls.
	Command []string `json:"command,omitempty"`
	// Before and After are the target file's state around the change.
	Before *FileState `json:"before,omitempty"`
	After  *FileState `json:"after,omitempty"`
	Result Result     `json:"result"`
	Error  string     `json:"error,omitempty"`
	// Undo is the command that reverses the action, when one exists.
	Undo string `json:"undo,omitempty"`
}

// Sink writes records. The daemon installs a file sink at startup; tests
// install their own.
type Sink interface {
	Write(Record) error
}

var (
	mu      sync.RWMutex
	sink    Sink
	host    string
	byActor = Daemon
)

// SetSink installs the process-wide sink. Passing nil disables recording,
// which is what a CLI that has not opened the log does.
func SetSink(s Sink, hostname string) {
	mu.Lock()
	defer mu.Unlock()
	sink, host = s, hostname
}

// SetDefaultActor declares which process is recording. The daemon leaves it at
// Daemon; a CLI that opens the log sets CLI. Actions an operator starts through
// the web UI run inside the daemon, so they record as Daemon here and carry the
// operator's address in the web UI's own action log.
func SetDefaultActor(a Actor) {
	mu.Lock()
	defer mu.Unlock()
	byActor = a
}

// DefaultActor returns the process-wide actor for call sites that have no more
// specific attribution.
func DefaultActor() Actor {
	mu.RLock()
	defer mu.RUnlock()
	return byActor
}

// Write records one action. It never returns an error: an action that
// happened must not be undone because its record could not be written, and a
// sink failure is reported through the daemon log by the sink itself.
func Write(r Record) {
	mu.RLock()
	s, h := sink, host
	mu.RUnlock()
	if s == nil {
		return
	}
	r.V = SchemaVersion
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now().UTC()
	}
	if r.Hostname == "" {
		r.Hostname = h
	}
	if r.Actor == "" {
		r.Actor = DefaultActor()
	}
	_ = s.Write(r)
}

// maxFileSize is the rotation threshold, matching the firewall and web UI
// logs this stream consolidates.
const maxFileSize = 10 * 1024 * 1024

// FileSink appends JSON lines to a file, rotating it once at the threshold.
type FileSink struct {
	resolve func() string
	mu      sync.Mutex
	path    string
	onErr   func(error)
}

// NewFileSink returns a sink writing to the file resolve names. The path is
// resolved on the first record and remembered, so installing a sink in a
// process that never records an action costs nothing: a CLI that only reads
// does not load config to work out where the log lives. onErr reports write
// failures; pass nil to discard them.
func NewFileSink(resolve func() string, onErr func(error)) *FileSink {
	return &FileSink{resolve: resolve, onErr: onErr}
}

// logPath returns the resolved path, resolving it once. The caller holds mu.
func (f *FileSink) logPath() string {
	if f.path == "" {
		f.path = f.resolve()
	}
	return f.path
}

// DefaultPath is where the daemon keeps the action log.
func DefaultPath(logDir string) string { return filepath.Join(logDir, "actions.jsonl") }

func (f *FileSink) Write(r Record) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	f.mu.Lock()
	defer f.mu.Unlock()
	path := f.logPath()
	if info, statErr := os.Stat(path); statErr == nil && info.Size() > maxFileSize {
		_ = os.Rename(path, path+".1")
	}
	// #nosec G304 G302 -- G304: path is derived from the operator-configured
	// log directory, not from attacker input. G302: 0640 matches the SIEM
	// audit log next to it, so a log shipper running as a non-root group
	// member can read this stream without running as root.
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		f.report(err)
		return err
	}
	defer func() { _ = fh.Close() }()
	if _, err := fh.Write(data); err != nil {
		f.report(err)
		return err
	}
	return nil
}

func (f *FileSink) report(err error) {
	if f.onErr != nil {
		f.onErr(err)
	}
}

// Stat captures a file's state for the Before or After field. A missing file
// is recorded as not existing rather than as an error: "the file was not
// there" is exactly what a reviewer needs to see after a quarantine.
func Stat(path string) *FileState {
	info, err := os.Lstat(path)
	if err != nil {
		return &FileState{}
	}
	st := &FileState{
		Exists: true,
		Size:   info.Size(),
		Mode:   info.Mode().Perm().String(),
	}
	fillOwner(st, info)
	if info.Mode().IsRegular() {
		if digest, err := digestFile(path); err == nil {
			st.Digest = digest
		}
	}
	return st
}

// maxDigestBytes bounds hashing so one enormous file cannot stall an action.
const maxDigestBytes = 64 * 1024 * 1024

func digestFile(path string) (string, error) {
	// #nosec G304 -- path is the file the action is already operating on.
	fh, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = fh.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(fh, maxDigestBytes)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Describe renders a record as one operator-readable line, used by `csm
// actions` and by the daemon log.
func (r Record) Describe() string {
	line := fmt.Sprintf("%s %s %s target=%s", r.Timestamp.UTC().Format(time.RFC3339), r.Op, r.Result, r.Target)
	if r.Account != "" {
		line += " account=" + r.Account
	}
	if len(r.Command) > 0 {
		line += " command=" + fmt.Sprintf("%q", r.Command)
	}
	if r.Before != nil && r.After != nil {
		line += fmt.Sprintf(" sha256 %s -> %s", shortDigest(r.Before), shortDigest(r.After))
	}
	if r.Error != "" {
		line += " error=" + r.Error
	}
	return line
}

func shortDigest(s *FileState) string {
	switch {
	case s == nil || !s.Exists:
		return "absent"
	case s.Digest == "":
		return "unhashed"
	default:
		return s.Digest[:12]
	}
}
