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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/safepath"
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
	// Action distinguishes changes within one operation, such as block and unblock.
	Action string `json:"action,omitempty"`
	// Actor and ActorDetail say who asked for it. ActorDetail carries the
	// operator's source address for a web UI action, or the command name for
	// a CLI action.
	Actor       Actor  `json:"actor"`
	ActorDetail string `json:"actor_detail,omitempty"`
	// FindingID ties the action to the finding that caused it, using the same
	// ID the SIEM audit log emits.
	FindingID  string `json:"finding_id,omitempty"`
	IncidentID string `json:"incident_id,omitempty"`
	// ActionID and ActionVersion identify a durable lifecycle event across retries.
	ActionID      string `json:"action_id,omitempty"`
	ActionVersion uint64 `json:"action_version,omitempty"`
	// UndoOf links a typed undo to its original action.
	UndoOf string `json:"undo_of,omitempty"`
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
	// RecoveryPath identifies retained file content and its metadata sidecar.
	RecoveryPath string `json:"recovery_path,omitempty"`
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

// A stuck filesystem or a broken sink must not hold a response worker forever.
// Bound both the wait and outstanding writes; normal writes complete before
// returning, including in short-lived CLI processes.
const writeTimeout = 250 * time.Millisecond

// Write records one action without propagating sink errors or panics. Recording
// is best effort: saturation or an unresponsive sink can cost an action record.
func Write(r Record) {
	mu.RLock()
	s, h, a := sink, host, byActor
	mu.RUnlock()
	if s == nil {
		return
	}
	actionWrites.write(s, prepareRecord(r, h, a))
}

func prepareRecord(r Record, h string, a Actor) Record {
	r.V = SchemaVersion
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now().UTC()
	}
	if r.Hostname == "" {
		r.Hostname = h
	}
	if r.Actor == "" {
		r.Actor = a
	}
	// A timed-out write can outlive the caller's buffers.
	r.Command = append([]string(nil), r.Command...)
	if r.Before != nil {
		before := *r.Before
		r.Before = &before
	}
	if r.After != nil {
		after := *r.After
		r.After = &after
	}
	return r
}

// ErrDurableUnavailable means no acknowledging sink is installed.
var ErrDurableUnavailable = errors.New("durable action log sink unavailable")

// ErrDurableUnacknowledged means delivery did not finish within the bounded
// wait. The sink may still complete; retry using the same action identity.
var ErrDurableUnacknowledged = errors.New("durable action log delivery unacknowledged")

// WriteDurable acknowledges only a sink's durable write. Delivery is at least
// once: a timeout can leave an append running after this call returns.
func WriteDurable(r Record) error {
	mu.RLock()
	s, h, a := sink, host, byActor
	mu.RUnlock()
	durable, ok := s.(interface{ WriteDurable(Record) error })
	if !ok {
		return ErrDurableUnavailable
	}
	acknowledgement := make(chan error, 1)
	actionWrites.write(durableWriteAdapter{write: durable.WriteDurable, acknowledgement: acknowledgement}, prepareRecord(r, h, a))
	select {
	case err := <-acknowledgement:
		return err
	default:
		return ErrDurableUnacknowledged
	}
}

type durableWriteAdapter struct {
	write           func(Record) error
	acknowledgement chan<- error
}

func (s durableWriteAdapter) Write(r Record) error {
	err := s.write(r)
	s.acknowledgement <- err
	return err
}

// maxFileSize is the rotation threshold, matching the firewall and web UI
// logs this stream consolidates.
const maxFileSize = 10 * 1024 * 1024

// FileSink appends JSON lines to a file, rotating it once at the threshold.
type FileSink struct {
	resolve  func() string
	mu       sync.Mutex
	path     string
	onErr    func(error)
	syncFile func(*os.File) error
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
	err := f.write(r, false)
	// Reporting outside the file lock lets a callback inspect or replace the
	// sink without deadlocking a completed action.
	if err != nil {
		f.report(err)
	}
	return err
}

// WriteDurable appends and syncs the record and its directory entries while
// holding the same cross-process lock as ordinary writes and rotation.
func (f *FileSink) WriteDurable(r Record) error {
	err := f.write(r, true)
	if err != nil {
		f.report(err)
	}
	return err
}

func (f *FileSink) sync(file *os.File) error {
	if f.syncFile != nil {
		return f.syncFile(file)
	}
	return file.Sync()
}

func (f *FileSink) write(r Record, durable bool) error {
	// Cleaning explanations and command errors may contain attacker-controlled
	// content. Keep individual lines readable by the bounded history reader.
	r.Reason = boundedDetail(r.Reason)
	r.Error = boundedDetail(r.Error)
	data, marshalErr := json.Marshal(r)
	if marshalErr != nil {
		return marshalErr
	}
	data = append(data, '\n')
	f.mu.Lock()
	defer f.mu.Unlock()
	path := f.logPath()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	// The daemon and CLI are separate writers. Lock a stable sidecar inode so
	// rotation cannot move another writer's newly opened log out from under it.
	lock, lockErr := openLogFile(path+".lock", os.O_RDWR|os.O_CREATE, 0640)
	if lockErr != nil {
		return lockErr
	}
	defer func() { _ = lock.Close() }()
	// #nosec G115 -- an open file descriptor fits in int on supported Unix hosts.
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }() // #nosec G115 -- open file descriptor.
	if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("action log is not a regular file: %s", path)
		}
		if info.Size() > maxFileSize {
			if err := os.Rename(path, path+".1"); err != nil {
				return err
			}
		}
	}
	fh, err := openLogFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	if _, err := fh.Write(data); err != nil {
		_ = fh.Close()
		return err
	}
	if durable {
		if err := f.sync(fh); err != nil {
			_ = fh.Close()
			return err
		}
	}
	if err := fh.Close(); err != nil {
		return err
	}
	if durable {
		return f.syncDirectories(filepath.Dir(path))
	}
	return nil
}

// Sync the whole ancestor chain because MkdirAll may have created multiple
// directories, and a retry must also acknowledge earlier uncertain creation.
func (f *FileSink) syncDirectories(dir string) error {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for {
		// #nosec G304 -- operator-configured log directory, opened only for syncing.
		directory, err := os.Open(absolute)
		if err != nil {
			return err
		}
		syncErr := f.sync(directory)
		closeErr := directory.Close()
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
		parent := filepath.Dir(absolute)
		if parent == absolute {
			return nil
		}
		absolute = parent
	}
}

func boundedDetail(value string) string {
	const limit = 4096
	if len(value) > limit {
		return strings.Clone(value[:limit]) + " [truncated]"
	}
	return value
}

func openLogFile(path string, flags int, mode os.FileMode) (*os.File, error) {
	// #nosec G304 G302 -- operator-configured log path; no symlinks or special
	// files. 0640 allows the log shipper's group to read the stream.
	f, err := os.OpenFile(path, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK, mode)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = fmt.Errorf("action log is not a regular file: %s", path)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// Read visits fixed snapshots of the rotated and current logs, oldest first.
// Both files are pinned before releasing the rotation lock, so a slow reader
// neither loses a rotated file nor holds up action writers.
func Read(path string, visit func(io.Reader) error) error {
	for {
		retry, err := readSnapshot(path, visit)
		if !retry {
			return err
		}
	}
}

func readSnapshot(path string, visit func(io.Reader) error) (bool, error) {
	lock, err := openLogFile(path+".lock", os.O_RDONLY, 0)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if lock != nil {
		defer func() { _ = lock.Close() }()
		// #nosec G115 -- an open file descriptor fits in int on supported Unix hosts.
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_SH); err != nil {
			return false, err
		}
	}
	var files []*os.File
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	var readers []io.Reader
	for _, name := range []string{path + ".1", path} {
		f, openErr := openLogFile(name, os.O_RDONLY, 0)
		if os.IsNotExist(openErr) {
			continue
		}
		if openErr != nil {
			return false, openErr
		}
		files = append(files, f)
		info, statErr := f.Stat()
		if statErr != nil {
			return false, statErr
		}
		readers = append(readers, io.NewSectionReader(f, 0, info.Size()))
	}
	if lock == nil {
		// The first writer may have created its lock while we opened the
		// files. Retry under that lock before exposing a mixed snapshot.
		if _, err := os.Lstat(path + ".lock"); err == nil {
			return true, nil
		} else if !os.IsNotExist(err) {
			return false, err
		}
	} else if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil { // #nosec G115 -- open file descriptor.
		return false, err
	}
	for _, reader := range readers {
		if err := visit(reader); err != nil {
			return false, err
		}
	}
	return false, nil
}

func (f *FileSink) report(err error) {
	if f.onErr != nil {
		f.onErr(err)
	}
}

// Metadata captures identity without opening or hashing the target. It is safe
// to use before a security action: evidence collection must not delay removal.
func Metadata(path string) *FileState {
	info, err := os.Lstat(path)
	if err != nil {
		return &FileState{}
	}
	return FromInfo(info)
}

// FromInfo describes metadata already pinned by the operation itself.
func FromInfo(info os.FileInfo) *FileState {
	if info == nil {
		return &FileState{}
	}
	st := &FileState{Exists: true, Size: info.Size(), Mode: info.Mode().String()}
	fillOwner(st, info)
	return st
}

// Stat hashes only a bounded regular file reached without following symlinks.
// No digest is better than a digest of a different inode or a truncated prefix.
func Stat(path string) *FileState {
	st := Metadata(path)
	if !st.Exists {
		return st
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return st
	}
	dir, err := safepath.OpenDirNoFollow(filepath.Dir(absolute))
	if err != nil {
		return st
	}
	defer func() { _ = dir.Close() }()
	f, err := dir.OpenFile(filepath.Base(absolute), os.O_RDONLY, 0)
	if err != nil {
		return st
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return st
	}
	st = FromInfo(info)
	if !info.Mode().IsRegular() || info.Size() > maxDigestBytes {
		return st
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxDigestBytes+1))
	if err != nil || n != info.Size() || n > maxDigestBytes {
		return st
	}
	after, err := f.Stat()
	if err == nil && after.Size() == info.Size() && after.ModTime().Equal(info.ModTime()) {
		st.Digest = hex.EncodeToString(h.Sum(nil))
	}
	return st
}

const maxDigestBytes = 64 * 1024 * 1024

// ContentState captures the exact bytes read or written through a pinned file.
func ContentState(info os.FileInfo, data []byte) *FileState {
	st := FromInfo(info)
	st.Size = int64(len(data))
	if len(data) <= maxDigestBytes {
		sum := sha256.Sum256(data)
		st.Digest = hex.EncodeToString(sum[:])
	}
	return st
}

// Describe renders a record as one operator-readable line, used by `csm
// actions` and by the daemon log.
func (r Record) Describe() string {
	line := fmt.Sprintf("%s %s %s target=%q", r.Timestamp.UTC().Format(time.RFC3339), r.Op, r.Result, r.Target)
	if r.Action != "" {
		line += fmt.Sprintf(" action=%q", r.Action)
	}
	if r.Account != "" {
		line += fmt.Sprintf(" account=%q", r.Account)
	}
	if len(r.Command) > 0 {
		line += " command=" + fmt.Sprintf("%q", r.Command)
	}
	if r.Before != nil && r.After != nil {
		line += fmt.Sprintf(" sha256 %s -> %s", shortDigest(r.Before), shortDigest(r.After))
	}
	if r.Error != "" {
		line += fmt.Sprintf(" error=%q", r.Error)
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
		return s.Digest[:min(12, len(s.Digest))]
	}
}
