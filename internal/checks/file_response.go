package checks

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/atomicio"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
)

const fileResponseStateName = "file-response.json"

// An attempt is reserved durably as failed before touching a customer file.
// Interrupted operations therefore keep both their budget and failure charge.
type fileResponseAttempt struct {
	At      time.Time `json:"at"`
	Account string    `json:"account"`
	Failed  bool      `json:"failed"`
	ID      string    `json:"id,omitempty"`
	Pending bool      `json:"pending,omitempty"`
}

type fileResponseState struct {
	Version  int                   `json:"version"`
	Attempts []fileResponseAttempt `json:"attempts"`
}

var fileResponseNow = time.Now
var writeFileResponseState = atomicio.AtomicWriteJSON
var activeFileResponses sync.Map

// A refusal leaves the customer file untouched and consumes attempt capacity,
// but does not indicate a failed response mechanism.
var errFileResponseRefused = errors.New("file response refused")

// fileResponseRefusal classifies an error as a refusal for errors.Is while
// keeping the refusing check's message. Manual remediation shares these
// checks, so the breaker's accounting must not show up in operator text.
type fileResponseRefusal struct{ err error }

func (r fileResponseRefusal) Error() string { return r.err.Error() }

func (r fileResponseRefusal) Unwrap() error { return r.err }

func (fileResponseRefusal) Is(target error) bool { return target == errFileResponseRefused }

func refuseFileResponse(err error) error { return fileResponseRefusal{err: err} }

func fileResponseSourceError(err error) error {
	// A socket replacement cannot be opened as a file and returns ENXIO
	// before the descriptor-based regular-file check can refuse it.
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ENXIO) {
		return refuseFileResponse(err)
	}
	return err
}

// runAutoFileResponse is shared by the automatic PHP/access-file cleaners and
// both quarantine entry points. Manual remediation does not enter this gate.
// A bounded process-shared lock protects reservation and outcome updates. The
// file action runs outside the lock, so a slow copy does not stall other slots.
func runAutoFileResponse(cfg *config.Config, path string, info os.FileInfo, apply func() error) *alert.Finding {
	now := fileResponseNow()
	notice := func(reason, account, detail string) *alert.Finding {
		return fileResponseNotice(cfg.StatePath, now, reason, account, detail)
	}
	if !info.Mode().IsRegular() {
		return notice("file_type", "", "Automatic file response refused a directory or special file. Review the detection and use manual remediation for this target.")
	}
	hostLimit, accountLimit, failureLimit := fileResponseLimits(cfg)
	if hostLimit < 1 || accountLimit < 1 || failureLimit < 1 || hostLimit > config.MaxFileResponseLimit || accountLimit > config.MaxFileResponseLimit || failureLimit > config.MaxFileResponseLimit {
		return notice("state", "", "Automatic file response is paused because its safety limits are invalid. Correct the configuration; detection continues.")
	}
	if cfg.StatePath == "" || !filepath.IsAbs(cfg.StatePath) {
		return notice("state", "", "Automatic file response is paused because its safety state directory is unavailable. Detection continues.")
	}
	// The operator-owned state directory is provisioned at daemon startup.
	// Never create a new directory here and silently reset a missing state root.
	lockPath := filepath.Join(cfg.StatePath, "file-response.lock")
	statePath := filepath.Join(cfg.StatePath, fileResponseStateName)
	_, account, _ := accountRootOf(path)
	attemptID := rand.Text()
	admitted := false
	reserved := func() *alert.Finding {
		lock, err := acquireFileResponseLock(lockPath)
		if err != nil {
			return notice("busy", "", "Automatic file response refused an attempt while its safety state was busy. Detection continues; review the original finding before retrying manually.")
		}
		defer lock.Close()
		state, err := readFileResponseState(statePath, now)
		if err != nil {
			csmlog.Warn("automatic file response state unreadable", "err", err)
			return notice("state", "", "Automatic file response is paused because its safety state cannot be read. Repair the state storage; detection continues.")
		}
		// Unknown paths share one budget. Finding text/TenantID must not select a
		// fresh account bucket, and UID alone conflates root-owned tenant files.
		used, failures, pending := fileResponseUsage(state, account)
		if failures >= failureLimit {
			return notice("failures", "", "Automatic file response is paused after repeated action failures in the rolling hour. Detection continues; inspect the action log and recovery copies before manual remediation.")
		}
		if failures+pending >= failureLimit {
			return notice("pending", "", "Automatic file response is paused while earlier file actions use the available failure capacity. Detection continues; review the original finding before manual remediation.")
		}
		if len(state.Attempts) >= hostLimit {
			return notice("host_limit", "", "Automatic file response reached its host limit for the rolling hour. Detection continues; review outstanding findings for manual remediation.")
		}
		if used >= accountLimit {
			return notice("account_limit", account, "Automatic file response reached its account limit for the rolling hour. Other accounts remain eligible; detection continues.")
		}
		state.Attempts = append(state.Attempts, fileResponseAttempt{At: now, Account: account, Failed: true, ID: attemptID, Pending: true})
		activeFileResponses.Store(attemptID, struct{}{})
		if err = writeFileResponseState(statePath, 0600, state); err != nil {
			activeFileResponses.Delete(attemptID)
			csmlog.Warn("automatic file response reservation failed", "err", err)
			return notice("state", "", "Automatic file response is paused because its safety reservation could not be saved. Detection continues.")
		}
		admitted = true
		return nil
	}()
	if !admitted {
		return reserved
	}
	defer activeFileResponses.Delete(attemptID)
	// The caller's snapshot predates budget persistence. Recheck it after that
	// I/O; the descriptor-based quarantine/cleaner checks it again when opening.
	current, err := os.Lstat(path)
	err = fileResponseSourceError(err)
	if err == nil && (!sameFileIdentity(info, current) || !sameContentShape(info, current)) {
		err = refuseFileResponse(errors.New("file changed before automatic response"))
	}
	if err == nil {
		err = apply()
	}
	failed := err != nil && !errors.Is(err, errFileResponseRefused)
	refused := errors.Is(err, errFileResponseRefused)
	if failed {
		csmlog.Warn("automatic file response failed", "path", path, "err", err)
	} else if refused {
		csmlog.Warn("automatic file response refused", "path", path, "err", err)
	}
	failures, err := finishFileResponseAttempt(lockPath, statePath, attemptID, now, failed)
	if err != nil {
		// The durable reservation remains charged even when outcome persistence
		// fails. Never retry the action or refund its slot based on this error.
		csmlog.Warn("automatic file response outcome save failed", "err", err)
		return notice("state", "", "An automatic file response completed but its safety outcome could not be saved. Its reservation remains charged; inspect storage and recovery evidence.")
	}
	if failed && failures >= failureLimit {
		return notice("failures", "", "Automatic file response is paused after repeated action failures in the rolling hour. Detection continues; inspect the action log and recovery copies before manual remediation.")
	}
	return nil
}

func acquireFileResponseLock(path string) (*os.File, error) {
	// #nosec G304 -- fixed filename inside the operator-configured state directory.
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = lock.Close()
		return nil, errors.New("safety lock is not a regular file")
	}
	// #nosec G115 -- an open POSIX file descriptor fits in int.
	if err := waitForFileResponseLock(int(lock.Fd()), 5*time.Second); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

func fileResponseUsage(state *fileResponseState, account string) (used, failures, pending int) {
	for _, attempt := range state.Attempts {
		if attempt.Account == account {
			used++
		}
		if !attempt.Failed {
			continue
		}
		if attempt.Pending {
			if _, active := activeFileResponses.Load(attempt.ID); active {
				pending++
				continue
			}
		}
		failures++
	}
	return used, failures, pending
}

func finishFileResponseAttempt(lockPath, statePath, attemptID string, now time.Time, failed bool) (int, error) {
	lock, err := acquireFileResponseLock(lockPath)
	if err != nil {
		return 0, err
	}
	defer lock.Close()
	state, err := readFileResponseState(statePath, now)
	if err != nil {
		return 0, err
	}
	found := false
	for i := range state.Attempts {
		if state.Attempts[i].ID != attemptID {
			continue
		}
		if found {
			return 0, errors.New("duplicate safety reservation")
		}
		found = true
		state.Attempts[i].Pending = false
		state.Attempts[i].Failed = failed
	}
	if !found {
		return 0, errors.New("safety reservation disappeared")
	}
	if err := writeFileResponseState(statePath, 0600, state); err != nil {
		return 0, err
	}
	_, failures, _ := fileResponseUsage(state, "")
	return failures, nil
}

func waitForFileResponseLock(fd int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EINTR) && !errors.Is(err, unix.EWOULDBLOCK) {
			return err
		}
		if !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func fileResponseLimits(cfg *config.Config) (host, account, failures int) {
	host, account, failures = cfg.AutoResponse.MaxFileActionsPerHour, cfg.AutoResponse.MaxFileActionsPerAccountPerHour, cfg.AutoResponse.MaxFileActionFailuresPerHour
	if host == 0 {
		host = config.DefaultMaxFileActionsPerHour
	}
	if account == 0 {
		account = config.DefaultMaxFileActionsPerAccountPerHour
	}
	if failures == 0 {
		failures = config.DefaultMaxFileActionFailuresPerHour
	}
	return
}

func readFileResponseState(path string, now time.Time) (*fileResponseState, error) {
	// #nosec G304 -- fixed filename inside the operator-owned state directory.
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return &fileResponseState{Version: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("safety state is not a regular file")
	}
	// Bound corrupted or externally replaced state before decoding.
	const maxSize = 4 << 20
	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSize {
		return nil, errors.New("safety state is too large")
	}
	var stored struct {
		Version  int             `json:"version"`
		Attempts json.RawMessage `json:"attempts"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, err
	}
	if stored.Version != 1 {
		return nil, errors.New("unknown safety state format")
	}
	if len(stored.Attempts) == 0 {
		return nil, errors.New("safety state is missing reservations")
	}
	// Account and Failed have meaningful zero values. Missing or null fields
	// must not silently turn a charged reservation into an unknown account
	// or a successful action and reopen capacity after state corruption.
	var attempts []struct {
		At      time.Time `json:"at"`
		Account *string   `json:"account"`
		Failed  *bool     `json:"failed"`
		ID      string    `json:"id"`
		Pending bool      `json:"pending"`
	}
	if err := json.Unmarshal(stored.Attempts, &attempts); err != nil {
		return nil, err
	}
	if attempts == nil {
		return nil, errors.New("safety state has null reservations")
	}
	state := &fileResponseState{Version: stored.Version}
	for _, attempt := range attempts {
		if attempt.At.IsZero() {
			return nil, errors.New("safety state has an undated reservation")
		}
		if attempt.Account == nil || attempt.Failed == nil || attempt.Pending && attempt.ID == "" {
			return nil, errors.New("safety state has an incomplete reservation")
		}
		// Future entries remain charged when the clock moves backwards.
		_, active := activeFileResponses.Load(attempt.ID)
		if attempt.At.After(now.Add(-time.Hour)) || attempt.Pending && active {
			state.Attempts = append(state.Attempts, fileResponseAttempt{At: attempt.At, Account: *attempt.Account, Failed: *attempt.Failed, ID: attempt.ID, Pending: attempt.Pending})
		}
	}
	return state, nil
}

var fileResponseNotices = struct {
	sync.Mutex
	last map[string]time.Time
}{last: make(map[string]time.Time)}

// Pause notices must not become a second alert flood during a detector or
// storage failure. Dedup is local (restart reports the pause again), bounded,
// and independent of the safety state so storage failures are reportable.
func fileResponseNotice(statePath string, now time.Time, reason, account, detail string) *alert.Finding {
	// An account-wide detector fault can exhaust many tenant budgets. Emit
	// one host notice per cause, so those warnings cannot spend the alert
	// budget that other non-critical detections need.
	key := statePath + "\x00" + reason
	fileResponseNotices.Lock()
	defer fileResponseNotices.Unlock()
	if last, ok := fileResponseNotices.last[key]; ok && now.Sub(last) < time.Hour {
		return nil
	}
	for k, last := range fileResponseNotices.last {
		if now.Sub(last) >= time.Hour {
			delete(fileResponseNotices.last, k)
		}
	}
	if len(fileResponseNotices.last) >= 1024 {
		// Do not let arbitrary state paths grow daemon memory without a bound.
		// Keep the existing notices suppressed until their window expires.
		return nil
	}
	fileResponseNotices.last[key] = now
	message := "Automatic file response paused"
	if account != "" {
		message = "Automatic file response paused for accounts at their limit"
	}
	return &alert.Finding{Check: "auto_response_paused", Severity: alert.Warning, Message: message, Details: detail, DedupKey: reason, Timestamp: now}
}
