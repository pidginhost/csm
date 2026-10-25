package parseworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	emime "github.com/pidginhost/csm/internal/mime"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/workerproc"
)

// ExtractTimeout bounds one message's extraction in a worker: three times the
// measured p99 (1.14 s for 200 messages up to the 25 MiB attachment cap on a
// 2-vCPU host), rounded up. It stays under the 5 s hold budget on purpose: a
// hanging message gets its verdict before the hold answers, so tempfail and
// quarantine still apply in time, and the scan slot is freed quickly. A
// message that kills the worker has none of its attachments scanned and
// follows email_av.fail_mode.
const ExtractTimeout = 4 * time.Second

// extractTimeout is a seam for tests.
var extractTimeout = ExtractTimeout

// ExtractorConfig configures the mail parse worker pool.
type ExtractorConfig struct {
	// Size is the slot count; values below 1 mean 4.
	Size      int
	Launch    func(slot int) workerproc.Launcher
	OnFailure func(reason string, err error)
	Log       func(string, ...any)
}

// Extractor extracts mail attachments in a pool of parse workers, one slot
// per caller goroutine.
type Extractor struct {
	pool *workerproc.Pool
}

// NewExtractor starts no worker; each slot's first Extract does.
func NewExtractor(cfg ExtractorConfig) (*Extractor, error) {
	size := cfg.Size
	if size < 1 {
		size = 4
	}
	pool, err := workerproc.NewPool(workerproc.PoolConfig{Size: size, Config: func(slot int) workerproc.Config {
		return workerproc.Config{
			Name:        fmt.Sprintf("parse worker (mail %d)", slot),
			Launch:      cfg.Launch(slot),
			Timeout:     extractTimeout,
			Limits:      ExtractLimits,
			Log:         cfg.Log,
			MaxJobs:     1000,
			IdleTimeout: 10 * time.Minute,
			OnFailure:   cfg.OnFailure,
			// A refused extraction delivers mail unscanned under the open
			// fail mode, so crafted mail must not be able to open the breaker.
			BreakOnSpawnOnly: true,
		}
	}})
	if err != nil {
		return nil, err
	}
	return &Extractor{pool: pool}, nil
}

// Size is the slot count.
func (e *Extractor) Size() int { return e.pool.Size() }

// Extract parses the message from its open -H and -D files on slot's worker.
// The parts come back as sealed memfds the caller closes with the result.
// A reply that fails validation kills the worker; the error then matches
// workerproc.ErrWorkerFailed with reason protocol.
func (e *Extractor) Extract(ctx context.Context, slot int, header, body *os.File, limits emime.Limits) (*emime.ExtractionResult, error) {
	payload, err := json.Marshal(ExtractArgs{
		MaxAttachmentSize: limits.MaxAttachmentSize,
		MaxArchiveDepth:   limits.MaxArchiveDepth,
		MaxArchiveFiles:   limits.MaxArchiveFiles,
		MaxExtractionSize: limits.MaxExtractionSize,
	})
	if err != nil {
		return nil, err
	}
	var res ExtractResult
	_, fds, err := e.pool.Call(ctx, slot, workerproc.Frame{Op: OpExtractMessage, Payload: payload}, []*os.File{header, body},
		func(reply workerproc.Frame, fds []*os.File) (bool, error) {
			res = ExtractResult{}
			return false, checkExtract(reply.Payload, fds, limits, &res)
		})
	if err != nil {
		return nil, err
	}
	out := &emime.ExtractionResult{
		Partial:                 res.Partial,
		PartialReason:           res.PartialReason,
		EncryptedEntriesOmitted: res.EncryptedEntriesOmitted,
		Direction:               res.Direction,
		From:                    res.From,
		To:                      res.To,
		Subject:                 res.Subject,
	}
	for _, en := range res.EncryptedEntries {
		out.EncryptedEntries = append(out.EncryptedEntries, emime.EncryptedArchiveEntry{ArchiveName: en.ArchiveName, Filename: en.Filename})
	}
	for i, p := range res.Parts {
		out.Parts = append(out.Parts, emime.ExtractedPart{
			Filename:    p.Filename,
			ContentType: p.ContentType,
			Size:        p.Size,
			File:        fds[i],
			Nested:      p.Nested,
			ArchiveName: p.ArchiveName,
		})
	}
	return out, nil
}

// checkExtract validates a worker's reply before anything uses it: the
// descriptors match the parts one for one, each is a sealed memfd of
// exactly the claimed, non-zero size within the caps, and every string is
// bounded, valid UTF-8 and in the form the worker's own sanitizing gives.
func checkExtract(payload []byte, fds []*os.File, limits emime.Limits, res *ExtractResult) error {
	// encoding/json replaces invalid UTF-8 instead of rejecting it.
	if !utf8.Valid(payload) {
		return errors.New("extract_message reply is not UTF-8")
	}
	// Parts may be null for an empty result, but it must be present. Keep
	// its raw value so a missing result cannot look like a clean message.
	var wire struct {
		*ExtractResult
		Parts json.RawMessage `json:"parts"`
	}
	wire.ExtractResult = res
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return fmt.Errorf("extract_message reply: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return errors.New("extract_message reply has trailing data")
	}
	if len(wire.Parts) == 0 {
		return errors.New("extract_message reply has no parts result")
	}
	parts := json.NewDecoder(bytes.NewReader(wire.Parts))
	parts.DisallowUnknownFields()
	if err := parts.Decode(&res.Parts); err != nil {
		return fmt.Errorf("extract_message parts: %w", err)
	}
	if len(res.Parts) > MaxParts || len(res.Parts) != len(fds) {
		return fmt.Errorf("reply lists %d parts with %d descriptors", len(res.Parts), len(fds))
	}
	var total int64
	for i, p := range res.Parts {
		if err := checkName(p.Filename, false); err != nil {
			return fmt.Errorf("part %d name: %w", i, err)
		}
		if err := checkName(p.ArchiveName, true); err != nil {
			return fmt.Errorf("part %d archive name: %w", i, err)
		}
		if err := checkText(p.ContentType, maxNameBytes); err != nil {
			return fmt.Errorf("part %d content type: %w", i, err)
		}
		if p.Size <= 0 || p.Size > limits.MaxAttachmentSize {
			return fmt.Errorf("part %d size %d outside 1..%d", i, p.Size, limits.MaxAttachmentSize)
		}
		if p.Size > limits.MaxExtractionSize-total {
			return fmt.Errorf("parts total more than %d bytes", limits.MaxExtractionSize)
		}
		total += p.Size
		if err := checkSealed(fds[i]); err != nil {
			return fmt.Errorf("part %d: %w", i, err)
		}
		st, err := fds[i].Stat()
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() || st.Size() != p.Size {
			return fmt.Errorf("part %d is %d bytes, reply says %d", i, st.Size(), p.Size)
		}
		// Seals and Stat also succeed on a write-only descriptor. Prove
		// the scanner can read it before accepting any part of the reply.
		var probe [1]byte
		if _, err := fds[i].ReadAt(probe[:], 0); err != nil {
			return fmt.Errorf("part %d is unreadable: %w", i, err)
		}
	}
	if len(res.EncryptedEntries) > MaxEncryptedEntries || res.EncryptedEntriesOmitted < 0 {
		return errors.New("reply names too many encrypted entries")
	}
	for _, en := range res.EncryptedEntries {
		if checkName(en.ArchiveName, false) != nil || checkName(en.Filename, false) != nil {
			return errors.New("encrypted entry name is not sanitized")
		}
	}
	if err := checkText(res.PartialReason, maxIncomplete); err != nil {
		return fmt.Errorf("partial reason: %w", err)
	}
	if len(res.To) > maxRecipients {
		return fmt.Errorf("reply lists %d recipients", len(res.To))
	}
	for _, s := range append([]string{res.From, res.Subject}, res.To...) {
		if err := checkText(s, maxHeaderBytes); err != nil {
			return fmt.Errorf("header: %w", err)
		}
	}
	switch res.Direction {
	case "", "inbound", "outbound":
	default:
		return fmt.Errorf("direction %q", res.Direction)
	}
	return nil
}

// checkName requires a name exactly as SanitizeAttachmentName leaves it.
func checkName(name string, optional bool) error {
	if optional && name == "" {
		return nil
	}
	if !utf8.ValidString(name) || len(name) > maxNameBytes || emime.SanitizeAttachmentName(name) != name {
		return errors.New("not a sanitized name")
	}
	return nil
}

// checkText bounds a string and refuses control characters other than tab,
// which could forge log lines where the string is printed.
func checkText(s string, max int) error {
	if !utf8.ValidString(s) || len(s) > max {
		return fmt.Errorf("invalid or longer than %d bytes", max)
	}
	if strings.IndexFunc(s, func(r rune) bool { return r != '\t' && unicode.IsControl(r) }) >= 0 {
		return errors.New("contains control characters")
	}
	return nil
}

// Stop kills every worker and refuses later extractions.
func (e *Extractor) Stop() error { return e.pool.Stop() }

// QueueStatuses publishes one requests row for the pool.
func (e *Extractor) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return e.pool.QueueStatuses(now)
}

// FileSizeLimit is the LimitFSIZE a mail worker needs: above the largest
// part it may write, never below the zip pool's 64 MiB.
func FileSizeLimit(maxAttachmentSize int64) uint64 {
	limit := uint64(64 << 20)
	if maxAttachmentSize > 0 {
		limit = max(limit, uint64(maxAttachmentSize)+1<<20) // #nosec G115 -- positive, checked above.
	}
	return limit
}
