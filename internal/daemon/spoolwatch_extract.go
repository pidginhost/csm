//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	emime "github.com/pidginhost/csm/internal/mime"
	"github.com/pidginhost/csm/internal/parseworker"
	"github.com/pidginhost/csm/internal/workerproc"
)

// spoolExtractTimeout backstops one extraction. The worker's own deadline
// (parseworker.ExtractTimeout) catches a hang and counts it against the
// worker; this one also covers starting the worker's unit. Var for tests.
var spoolExtractTimeout = parseworker.ExtractTimeout + 10*time.Second

// errNoExtractor stands for parse workers that could not be set up.
var errNoExtractor = errors.New("no mail parse worker")

const (
	// repeatFailureReason is the partial reason of a message that is not
	// unpacked again because it made workers fail before.
	repeatFailureReason = "parse worker failed on this message before"
	// outcomeSkipped is the job outcome of such a message.
	outcomeSkipped = "skipped"
	// sourceKillLimit worker kills from one source, each within
	// sourceKillWindow of the one before, raise a High finding.
	sourceKillLimit  = 3
	sourceKillWindow = 10 * time.Minute
)

func (sw *SpoolWatcher) initStrikes() {
	sw.mailStrikes = workerproc.NewStrikes()
	sw.sourceKills = workerproc.NewStrikesWith(sourceKillLimit, sourceKillWindow)
}

// countedKill reports a failure the worker's input caused: a timeout, a
// memory kill, a crash or a rejected reply. Failed starts, the breaker,
// cancellation and shutdown are not the message's doing.
func countedKill(err error) bool {
	switch workerproc.FailureReason(err) {
	case workerproc.ReasonTimeout, workerproc.ReasonOOM, workerproc.ReasonCrash, workerproc.ReasonProtocol:
		return true
	}
	return false
}

// openSpoolHeader opens the -H file of the message whose -D is open on
// bodyFD. It follows no link and does not block on a FIFO, and the result
// must be a regular file on the body's filesystem: the worker is given
// whatever this opens. A missing file keeps its ENOENT for the reception race
// (MAIL-03).
func openSpoolHeader(path string, bodyFD int) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var hs, bs unix.Stat_t
	err = unix.Fstat(fd, &hs)
	if err == nil {
		err = unix.Fstat(bodyFD, &bs)
	}
	switch {
	case err != nil:
	case hs.Mode&unix.S_IFMT != unix.S_IFREG:
		err = fmt.Errorf("spool header %s is not a regular file", path)
	case hs.Dev != bs.Dev:
		err = fmt.Errorf("spool header %s is not on the spool filesystem", path)
	default:
		err = unix.SetNonblock(fd, false)
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// dupEventBody gives extraction independent ownership of the event's body
// descriptor while preserving close-on-exec on the copy.
func dupEventBody(fd int) (*os.File, error) {
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0) // #nosec G115 -- POSIX fd is non-negative.
	if err != nil {
		return nil, fmt.Errorf("duplicating spool body descriptor: %w", err)
	}
	var st unix.Stat_t
	if err = unix.Fstat(dup, &st); err == nil && st.Mode&unix.S_IFMT != unix.S_IFREG {
		err = errors.New("spool body is not a regular file")
	}
	if err != nil {
		_ = unix.Close(dup)
		return nil, err
	}
	return os.NewFile(uintptr(dup), "spool body"), nil // #nosec G115 -- POSIX fd is non-negative.
}

// extractSpoolMessage extracts the event's message in the event's worker
// slot. An error means the spool files could not be opened; a worker that
// fails, or no worker at all, gives a partial result naming why.
func (sw *SpoolWatcher) extractSpoolMessage(evt spoolEvent, msgID, headerPath string, limits emime.Limits) (*emime.ExtractionResult, error) {
	body, err := dupEventBody(evt.fd)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()
	header, err := openSpoolHeader(headerPath, evt.fd)
	if err != nil {
		return nil, err
	}
	defer func() { _ = header.Close() }()
	if sw.extractor == nil {
		return sw.extractFailed(msgID, evt.source, errNoExtractor), nil
	}
	if sw.mailStrikes != nil && sw.mailStrikes.Blocked(msgID) {
		recordParseJob("mail", outcomeSkipped, 0)
		fmt.Fprintf(os.Stderr, "[%s] spool watcher: not unpacking %s again: parse workers failed on it before\n", ts(), msgID)
		return &emime.ExtractionResult{Partial: true, PartialReason: repeatFailureReason}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), spoolExtractTimeout)
	defer cancel()
	extraction, err := sw.extractor.Extract(ctx, evt.slot, header, body, limits)
	if err != nil {
		if countedKill(err) {
			sw.recordWorkerKill(msgID, evt.source)
		}
		return sw.extractFailed(msgID, evt.source, err), nil
	}
	return extraction, nil
}

// recordWorkerKill charges a worker kill to the message and its source. A
// source whose messages keep killing workers is named in a High finding.
func (sw *SpoolWatcher) recordWorkerKill(msgID, source string) {
	if sw.mailStrikes == nil {
		return
	}
	sw.mailStrikes.Record(msgID)
	if source == "" {
		return
	}
	sw.sourceKills.Record(source)
	if sw.sourceKills.Blocked(source) {
		sw.emitLimited("email_av_parse_worker_source", alert.High, sourceKillWindow,
			fmt.Sprintf("Messages from source %q killed the attachment parse worker %d times, each within %s of the one before. Their attachments were not scanned and followed email_av.fail_mode. This looks like crafted mail; consider blocking the source.", source, sourceKillLimit, sourceKillWindow))
	}
}

// sourceText names a message source for a finding.
func sourceText(source string) string {
	if source == "" {
		return "an unknown source"
	}
	return fmt.Sprintf("source %q", source)
}

// extractFailed reports a failed extraction and turns it into a partial
// result, which follows fail_mode and is never clean.
func (sw *SpoolWatcher) extractFailed(msgID, source string, err error) *emime.ExtractionResult {
	reason, isolation := extractFailureReason(err)
	fmt.Fprintf(os.Stderr, "[%s] spool watcher: extraction failed for %s: %v\n", ts(), msgID, err)
	switch {
	case errors.Is(err, workerproc.ErrStopped):
		// The daemon is shutting down; that is not an outage.
	case isolation:
		sw.emitLimited("email_av_isolation_unavailable", alert.Critical, isolationAlertInterval,
			fmt.Sprintf("Email attachments cannot be unpacked in an isolated worker (%s); message %s was handled as an incomplete scan under email_av.fail_mode: %v", reason, msgID, err))
	default:
		sw.emitLimited("email_av_parse_worker_failed", alert.Warning, time.Minute,
			fmt.Sprintf("Parse worker failed on message %s from %s (%s); the message was handled as an incomplete scan under email_av.fail_mode", msgID, sourceText(source), reason))
		if workerproc.FailureReason(err) == workerproc.ReasonProtocol {
			sw.emitLimited("email_av_parse_worker_rejected", alert.Critical, time.Hour,
				fmt.Sprintf("Parse worker sent an invalid reply for message %s and was killed; a crafted message may have taken it over", msgID))
		}
	}
	return &emime.ExtractionResult{Partial: true, PartialReason: reason}
}

// extractFailureReason names an extraction failure for the partial result,
// and says whether isolation itself is unavailable rather than one worker
// having failed.
func extractFailureReason(err error) (reason string, isolation bool) {
	switch {
	case errors.Is(err, workerproc.ErrWorkerFailed):
		switch workerproc.FailureReason(err) {
		case workerproc.ReasonTimeout:
			return "parse worker timed out", false
		case workerproc.ReasonOOM:
			return "parse worker ran out of memory", false
		case workerproc.ReasonProtocol:
			return "parse worker reply rejected", false
		default:
			return "parse worker crashed", false
		}
	case errors.Is(err, context.DeadlineExceeded):
		return "parse worker timed out", false
	case errors.Is(err, workerproc.ErrBreakerOpen):
		return "parse worker failing repeatedly", true
	default:
		return "parse isolation unavailable", true
	}
}

// emitLimited emits a finding at most once per interval per check.
func (sw *SpoolWatcher) emitLimited(check string, severity alert.Severity, interval time.Duration, message string) {
	l := sw.findings
	if l == nil {
		l = &sw.ownFindings
	}
	l.emit(sw.alertCh, check, severity, interval, message)
}

// removeLegacyEmailAVTempDir removes the attachment staging directory of
// earlier versions. A link in its place is removed, never followed.
func removeLegacyEmailAVTempDir(statePath string) {
	if statePath == "" {
		return
	}
	dir := filepath.Join(statePath, "emailav-tmp")
	if _, err := os.Lstat(dir); err != nil {
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] spool watcher: removing old attachment directory %s: %v\n", ts(), dir, err)
		return
	}
	fmt.Fprintf(os.Stderr, "[%s] spool watcher: removed old attachment directory %s\n", ts(), dir)
}
