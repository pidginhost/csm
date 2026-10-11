package antispam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxRequestBytes bounds one worker request (spec section 4.2).
const MaxRequestBytes = 16 << 10

// Worker operations.
const (
	OpApply  = "apply"
	OpRemove = "remove"
)

// Rollback states a Result reports.
const (
	// RollbackNone: the worker changed nothing.
	RollbackNone = "none"
	// RollbackVerified: every change was undone, rebuilt, reloaded and probed.
	RollbackVerified = "verified"
	// RollbackFailed: the prior state is not confirmed; reconcile must repair.
	RollbackFailed = "failed"
)

// Request is the one JSON object the daemon sends to the antispam worker. It
// carries settings only: no path, command or Exim text.
type Request struct {
	Operation    string  `json:"operation"`
	Enabled      *bool   `json:"enabled,omitempty"`
	DryRun       *bool   `json:"dry_run,omitempty"`
	RspamdSocket *string `json:"rspamd_socket,omitempty"`
	RejectScore  *int    `json:"reject_score,omitempty"`
	TagScore     *int    `json:"tag_score,omitempty"`
}

// ApplyRequest is the request that installs s.
func ApplyRequest(s Settings) Request {
	enabled := true
	return Request{
		Operation:    OpApply,
		Enabled:      &enabled,
		DryRun:       &s.DryRun,
		RspamdSocket: &s.Socket,
		RejectScore:  &s.RejectScore,
		TagScore:     &s.TagScore,
	}
}

// RemoveRequest is the request that removes CSM's antispam integration.
func RemoveRequest() Request {
	return Request{Operation: OpRemove}
}

var requestKeys = map[string]bool{
	"operation": true, "enabled": true, "dry_run": true,
	"rspamd_socket": true, "reject_score": true, "tag_score": true,
}

// DecodeRequest validates one request before any side effect. Settings is
// set for an apply. Error messages never repeat the input.
func DecodeRequest(data []byte) (Request, Settings, error) {
	if len(data) > MaxRequestBytes {
		return Request{}, Settings{}, fmt.Errorf("request exceeds %d bytes", MaxRequestBytes)
	}
	keys, err := requestObjectKeys(data)
	if err != nil {
		return Request{}, Settings{}, err
	}
	var r Request
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&r); err != nil {
		return Request{}, Settings{}, errors.New("request has a value of the wrong type")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Request{}, Settings{}, errors.New("request has trailing data")
	}
	switch r.Operation {
	case OpApply:
		if r.Enabled == nil || r.DryRun == nil || r.RspamdSocket == nil || r.RejectScore == nil || r.TagScore == nil {
			return Request{}, Settings{}, errors.New("apply needs enabled, dry_run, rspamd_socket, reject_score and tag_score")
		}
		if !*r.Enabled {
			return Request{}, Settings{}, errors.New("apply needs enabled true")
		}
		s := Settings{DryRun: *r.DryRun, Socket: *r.RspamdSocket, RejectScore: *r.RejectScore, TagScore: *r.TagScore}
		if err := s.Validate(); err != nil {
			return Request{}, Settings{}, err
		}
		return r, s, nil
	case OpRemove:
		if keys != 1 {
			return Request{}, Settings{}, errors.New("remove carries only the operation")
		}
		return r, Settings{}, nil
	default:
		return Request{}, Settings{}, errors.New("unsupported operation")
	}
}

// requestObjectKeys checks that data is one flat JSON object whose keys are
// known, exact and unique, and returns how many it has. encoding/json would
// otherwise match keys case-insensitively and keep the last of duplicates.
func requestObjectKeys(data []byte) (int, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return 0, errors.New("request is not a JSON object")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return 0, errors.New("request is not valid JSON")
		}
		key, _ := token.(string)
		if !requestKeys[key] {
			return 0, errors.New("request has an unknown field")
		}
		if seen[key] {
			return 0, errors.New("request repeats a field")
		}
		seen[key] = true
		value, err := decoder.Token()
		if err != nil {
			return 0, errors.New("request is not valid JSON")
		}
		if _, nested := value.(json.Delim); nested {
			return 0, errors.New("request has a nested value")
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return 0, errors.New("request is not valid JSON")
	}
	return len(seen), nil
}

// Result is the one JSON line the worker writes to stdout.
type Result struct {
	Operation string `json:"operation,omitempty"`
	OK        bool   `json:"ok"`
	// Busy means another CSM transaction held the Exim lock: retry later.
	Busy       bool   `json:"busy,omitempty"`
	FailedStep string `json:"failed_step,omitempty"`
	Rollback   string `json:"rollback,omitempty"`
	// Generation identifies the installed content after a successful apply.
	Generation string `json:"generation,omitempty"`
	Error      string `json:"error,omitempty"`
}

// ParseResult reads the worker's stdout, which holds exactly one Result.
func ParseResult(out []byte) (Result, error) {
	var r Result
	decoder := json.NewDecoder(bytes.NewReader(out))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		return Result{}, fmt.Errorf("worker result: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Result{}, errors.New("worker result has trailing data")
	}
	return r, nil
}
