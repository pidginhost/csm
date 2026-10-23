package antispam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
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

// FeedsCheckStep is the failed step of an apply whose rspamd blocklist rules
// could not be verified against CSM's settings; the daemon then holds feeds off.
const FeedsCheckStep = "feeds_check"

// Request is the one JSON object the daemon sends to the antispam worker. It
// carries settings only: no command or Exim text. Its paths are the scan
// socket, DQS key file and learning directory; keys never travel, because
// the request is recorded on disk.
type Request struct {
	Operation    string  `json:"operation"`
	Enabled      *bool   `json:"enabled,omitempty"`
	DryRun       *bool   `json:"dry_run,omitempty"`
	RspamdSocket *string `json:"rspamd_socket,omitempty"`
	RejectScore  *int    `json:"reject_score,omitempty"`
	TagScore     *int    `json:"tag_score,omitempty"`
	// Feeds and SkipMaps are comma-separated names.
	Feeds      *string `json:"feeds,omitempty"`
	SkipMaps   *string `json:"skip_maps,omitempty"`
	SkipScores *bool   `json:"skip_scores,omitempty"`
	DQSKeyFile *string `json:"dqs_key_file,omitempty"`
	// Learning fields are omitted when learning is off, so older records
	// keep their form.
	Learning    *bool   `json:"learning,omitempty"`
	LearningDir *string `json:"learning_dir,omitempty"`
	Roundcube   *bool   `json:"roundcube,omitempty"`
}

// ApplyRequest is the request that installs s.
func ApplyRequest(s Settings) Request {
	enabled := true
	r := Request{
		Operation:    OpApply,
		Enabled:      &enabled,
		DryRun:       &s.DryRun,
		RspamdSocket: &s.Socket,
		RejectScore:  &s.RejectScore,
		TagScore:     &s.TagScore,
	}
	if len(s.Feeds) > 0 {
		v := strings.Join(s.Feeds, ",")
		r.Feeds = &v
	}
	if len(s.SkipMaps) > 0 {
		v := strings.Join(s.SkipMaps, ",")
		r.SkipMaps = &v
	}
	if s.SkipScores {
		skip := true
		r.SkipScores = &skip
	}
	if s.DQSKeyFile != "" {
		v := s.DQSKeyFile
		r.DQSKeyFile = &v
	}
	if s.Learning {
		learning, dir := true, s.LearningDir
		r.Learning, r.LearningDir = &learning, &dir
	}
	if s.Roundcube {
		roundcube := true
		r.Roundcube = &roundcube
	}
	return r
}

// RemoveRequest is the request that removes CSM's antispam integration.
func RemoveRequest() Request {
	return Request{Operation: OpRemove}
}

var requestKeys = map[string]bool{
	"operation": true, "enabled": true, "dry_run": true,
	"rspamd_socket": true, "reject_score": true, "tag_score": true,
	"feeds": true, "skip_maps": true, "skip_scores": true, "dqs_key_file": true,
	"learning": true, "learning_dir": true, "roundcube": true,
}

// splitNames reads a comma-separated request field.
func splitNames(p *string) []string {
	if p == nil || *p == "" {
		return nil
	}
	return strings.Split(*p, ",")
}

// DecodeRequest validates one request before any side effect. Settings is
// set for an apply. Error messages repeat no input except the one invalid
// socket character ValidateSocket names.
func DecodeRequest(data []byte) (Request, Settings, error) {
	if len(data) > MaxRequestBytes {
		return Request{}, Settings{}, fmt.Errorf("request exceeds %d bytes", MaxRequestBytes)
	}
	fields, err := objectFields(data, requestKeys, "request")
	if err != nil {
		return Request{}, Settings{}, err
	}
	for _, key := range []string{"feeds", "skip_maps", "skip_scores", "dqs_key_file", "learning_dir", "learning", "roundcube"} {
		if value, present := fields[key]; present {
			var valid bool
			if key == "skip_scores" || key == "learning" || key == "roundcube" {
				_, valid = value.(bool)
			} else {
				_, valid = value.(string)
			}
			if !valid {
				return Request{}, Settings{}, errors.New("request has a value of the wrong type")
			}
		}
	}
	var r Request
	if err := json.Unmarshal(data, &r); err != nil {
		return Request{}, Settings{}, errors.New("request has a value of the wrong type")
	}
	switch r.Operation {
	case OpApply:
		if r.Enabled == nil || r.DryRun == nil || r.RspamdSocket == nil || r.RejectScore == nil || r.TagScore == nil {
			return Request{}, Settings{}, errors.New("apply needs enabled, dry_run, rspamd_socket, reject_score and tag_score")
		}
		if !*r.Enabled {
			return Request{}, Settings{}, errors.New("apply needs enabled true")
		}
		s := Settings{DryRun: *r.DryRun, Socket: *r.RspamdSocket, RejectScore: *r.RejectScore, TagScore: *r.TagScore,
			Feeds: splitNames(r.Feeds), SkipMaps: splitNames(r.SkipMaps)}
		if r.DQSKeyFile != nil {
			s.DQSKeyFile = *r.DQSKeyFile
		}
		s.SkipScores = r.SkipScores != nil && *r.SkipScores
		s.Learning = r.Learning != nil && *r.Learning
		s.Roundcube = r.Roundcube != nil && *r.Roundcube
		if s.Learning && r.LearningDir != nil {
			s.LearningDir = *r.LearningDir
		}
		if err := s.Validate(); err != nil {
			return Request{}, Settings{}, err
		}
		return r, s, nil
	case OpRemove:
		if len(fields) != 1 {
			return Request{}, Settings{}, errors.New("remove carries only the operation")
		}
		return r, Settings{}, nil
	default:
		return Request{}, Settings{}, errors.New("unsupported operation")
	}
}

// objectFields rejects ambiguous keys before encoding/json can match them
// case-insensitively or keep only the last duplicate.
func objectFields(data []byte, allowed map[string]bool, label string) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("%s is not a JSON object", label)
	}
	fields := make(map[string]any)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("%s is not valid JSON", label)
		}
		key, _ := token.(string)
		if !allowed[key] {
			return nil, fmt.Errorf("%s has an unknown field", label)
		}
		if _, seen := fields[key]; seen {
			return nil, fmt.Errorf("%s repeats a field", label)
		}
		value, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("%s is not valid JSON", label)
		}
		if _, nested := value.(json.Delim); nested {
			return nil, fmt.Errorf("%s has a nested value", label)
		}
		fields[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, fmt.Errorf("%s is not valid JSON", label)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s has trailing data", label)
	}
	return fields, nil
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
	// Roundcube is set when a successful transaction could not verify the
	// webmail include; the rest of the change stands (spec 6.4).
	Roundcube string `json:"roundcube,omitempty"`
}

// ErrorSummary keeps Result.Error on one line for logs and findings.
func ErrorSummary(s string) string {
	return strings.NewReplacer("\r\n", "; ", "\r", "; ", "\n", "; ").Replace(s)
}

var resultKeys = map[string]bool{
	"operation": true, "ok": true, "busy": true, "failed_step": true,
	"rollback": true, "generation": true, "error": true, "roundcube": true,
}

// ParseResult reads one unambiguous worker report. Invalid or contradictory
// reports return no result, so callers cannot mistake them for completed work.
func ParseResult(out []byte) (Result, error) {
	fields, err := objectFields(out, resultKeys, "worker result")
	if err != nil {
		return Result{}, err
	}
	if _, present := fields["ok"]; !present {
		return Result{}, errors.New("worker result needs ok")
	}
	for key, value := range fields {
		var valid bool
		if key == "ok" || key == "busy" {
			_, valid = value.(bool)
		} else {
			_, valid = value.(string)
		}
		if !valid {
			return Result{}, errors.New("worker result has a value of the wrong type")
		}
	}
	var r Result
	if err := json.Unmarshal(out, &r); err != nil {
		return Result{}, errors.New("worker result is not valid JSON")
	}
	if err := r.Validate(); err != nil {
		return Result{}, err
	}
	return r, nil
}

// Validate checks a result's invariants: success carries a generation only
// for apply, failure names its step and rollback, busy only at the lock.
func (r Result) Validate() error {
	if r.Operation != OpApply && r.Operation != OpRemove &&
		(r.Operation != "" || r.OK || r.FailedStep != "request") {
		return errors.New("worker result has an unsupported operation")
	}
	if r.Roundcube != "" && (!r.OK || !strings.HasPrefix(r.Roundcube, RoundcubeUnavailable)) {
		return errors.New("worker result reports an unexpected Roundcube state")
	}
	if r.OK {
		if r.Busy || r.FailedStep != "" || r.Error != "" || (r.Rollback != "" && r.Rollback != RollbackNone) {
			return errors.New("worker result reports both success and failure")
		}
		if (r.Operation == OpApply) != (r.Generation != "") {
			return errors.New("worker result needs a generation only for successful apply")
		}
		return nil
	}
	if r.FailedStep == "" || r.Generation != "" {
		return errors.New("worker failure needs a failed step and no generation")
	}
	if r.Rollback != RollbackNone && r.Rollback != RollbackVerified && r.Rollback != RollbackFailed {
		return errors.New("worker failure needs a valid rollback state")
	}
	if r.Busy && r.FailedStep != "lock" {
		return errors.New("worker result reports busy outside the lock step")
	}
	if (r.FailedStep == "request" || r.FailedStep == "lock") && r.Rollback != RollbackNone {
		return errors.New("worker result reports changes before the transaction")
	}
	return nil
}
