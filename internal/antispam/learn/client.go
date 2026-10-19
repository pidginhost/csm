package learn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/hostfacts"
)

// Limits of the native calls (spec 7.4, 14). RequestTimeout is provisional
// until Plan C's benchmark records a measurement.
const (
	RequestTimeout = 5 * time.Second
	// SyncTimeout bounds rspamadm control fuzzy_sync.
	SyncTimeout = 10 * time.Second
	// MaxBody is the snapshot limit, headers and attachments included.
	MaxBody = 10 << 20
	// MaxExplicitDigests matches the inspection plugin's own cap.
	MaxExplicitDigests = 64
	maxInspectReply    = 256 << 10
	maxMutationReply   = 64 << 10
)

// InspectPath is the CSM inspection plugin's controller path.
const InspectPath = "/plugins/csm_learning/inspect"

// SyntheticMessage is the task body of an exact-only inspection; explicit
// digest checks ignore the body's own hashes, so no retained mail is sent.
const SyntheticMessage = "From: csm@localhost\r\nSubject: csm learning audit\r\n\r\naudit\r\n"

// Client errors. A rejected reply is a definite answer from the controller,
// yet it does not prove storage left the value unchanged (an IO timeout
// reply can follow an applied write), so callers reconcile by reading.
var (
	ErrUncertain = errors.New("request sent; outcome unknown")
	ErrRejected  = errors.New("controller refused the request")
	ErrPeer      = errors.New("controller socket is not served by rspamd")
)

// Client speaks the native calls of spec 7.4 over rspamd's private
// controller socket. Mutations are never repeated automatically.
type Client struct {
	Controller string
	RspamdUID  int
	// Run runs rspamadm; nil means hostfacts.RunCommand.
	Run func(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult
}

// Inspect inspects a message: one result per distinct text digest, hits
// carrying the stored anchor they matched.
func (c Client) Inspect(ctx context.Context, body []byte) (Inspection, error) {
	if len(body) > MaxBody {
		return Inspection{}, errors.New("message is larger than the learning limit")
	}
	reply, err := c.inspect(ctx, InspectPath, body)
	if err != nil {
		return Inspection{}, err
	}
	return ParseInspection(reply, nil)
}

// InspectDigests runs an exact-only check of full digests.
func (c Client) InspectDigests(ctx context.Context, ds []Digest) (Inspection, error) {
	if len(ds) == 0 || len(ds) > MaxExplicitDigests {
		return Inspection{}, errors.New("exact inspection needs 1 to 64 digests")
	}
	list := make([]string, len(ds))
	for i, d := range ds {
		if _, err := ParseDigest(string(d)); err != nil {
			return Inspection{}, err
		}
		list[i] = string(d)
	}
	reply, err := c.inspect(ctx, InspectPath+"?digests="+strings.Join(list, ","), []byte(SyntheticMessage))
	if err != nil {
		return Inspection{}, err
	}
	return ParseInspection(reply, ds)
}

func (c Client) inspect(ctx context.Context, path string, body []byte) ([]byte, error) {
	status, reply, err := c.do(ctx, path, nil, body, maxInspectReply)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%w: inspection returned HTTP %d", ErrRejected, status)
	}
	return reply, nil
}

// Add sends one /fuzzyadd of the anchor body with weight w.
func (c Client) Add(ctx context.Context, body []byte, w int32) error {
	if w <= 0 {
		return errors.New("weight must be positive")
	}
	if len(body) > MaxBody {
		return errors.New("message is larger than the learning limit")
	}
	return c.mutate(ctx, "/fuzzyadd", map[string]string{"Flag": "1", "Weight": strconv.Itoa(int(w))}, body)
}

// DeleteHash sends one /fuzzydelhash of a full digest. Success alone proves
// nothing; a later exact check must observe absence.
func (c Client) DeleteHash(ctx context.Context, d Digest) error {
	if _, err := ParseDigest(string(d)); err != nil {
		return err
	}
	return c.mutate(ctx, "/fuzzydelhash", map[string]string{"Flag": "1", "Hash": string(d)}, nil)
}

func (c Client) mutate(ctx context.Context, path string, hdr map[string]string, body []byte) error {
	status, reply, err := c.do(ctx, path, hdr, body, maxMutationReply)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("%w: mutation returned HTTP %d", ErrRejected, status)
	}
	fields, err := objectFields(reply, "success", "hashes", "error")
	if err != nil {
		return ErrUncertain
	}
	if fields["error"] != nil {
		var message string
		if fields["success"] == nil && json.Unmarshal(fields["error"], &message) == nil && message != "" {
			return ErrRejected
		}
		return ErrUncertain
	}
	var success bool
	if json.Unmarshal(fields["success"], &success) != nil {
		return ErrUncertain
	}
	if !success {
		return ErrRejected
	}
	if raw := fields["hashes"]; raw != nil {
		var hashes []json.RawMessage
		if uclList(raw, &hashes) != nil {
			return ErrUncertain
		}
		for _, rawHash := range hashes {
			var hash string
			if json.Unmarshal(rawHash, &hash) != nil {
				return ErrUncertain
			}
			if _, err := ParseDigest(hash); err != nil {
				return ErrUncertain
			}
		}
	}
	return nil
}

func (c Client) do(ctx context.Context, path string, hdr map[string]string, body []byte, limit int64) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	status, reply, err := hostfacts.ControllerDo(ctx, c.Controller, c.RspamdUID, http.MethodPost, path, hdr, body, limit)
	if err != nil {
		// The sanitized transport error keeps send status but drops the
		// cause. Cancellation must not spend a message's retry allowance.
		err = errors.Join(err, ctx.Err())
	}
	switch {
	case errors.Is(err, hostfacts.ErrControllerPeer):
		return 0, nil, ErrPeer
	case errors.Is(err, hostfacts.ErrControllerNoReply):
		return 0, nil, fmt.Errorf("%w: %w", ErrUncertain, err)
	case err != nil:
		return 0, nil, err
	}
	return status, bytes.Clone(reply), nil
}

// Sync asks the fuzzy worker to flush queued updates. It does not wait for
// Redis; callers verify with exact checks.
func (c Client) Sync(ctx context.Context) error {
	run := c.Run
	if run == nil {
		run = hostfacts.RunCommand
	}
	if res := run(ctx, SyncTimeout, "rspamadm", "control", "fuzzy_sync"); res.Err != nil {
		return errors.New("rspamadm control fuzzy_sync failed")
	}
	return nil
}
