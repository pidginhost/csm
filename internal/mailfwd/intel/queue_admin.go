package intel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/systemdrun"
)

// ErrNotQueued means exim no longer holds the message: it was delivered,
// returned to its sender or removed.
var ErrNotQueued = errors.New("message is not in the queue")

// Outcomes of a queue action, read from the queue after the action ran.
const (
	OutcomeRemoved        = "removed"
	OutcomeBounced        = "bounced"
	OutcomeAttemptStarted = "attempt_started"
	OutcomeThawed         = "thawed"
	OutcomeGone           = "gone"
	OutcomeUnchanged      = "unchanged"
)

// queueActionFlags maps each per-message action to its exim option.
var queueActionFlags = map[string]string{
	"retry":  "-M",   // delivery attempt now; thaws a frozen message first
	"bounce": "-Mg",  // give up and return the message to its sender
	"delete": "-Mrm", // remove without telling the sender
	"thaw":   "-Mt",
}

// ValidQueueAction reports whether action names a per-message queue action.
func ValidQueueAction(action string) bool {
	_, ok := queueActionFlags[action]
	return ok
}

// QueueAdmin reads single queued messages and runs the per-message actions an
// administrator can take on them.
type QueueAdmin interface {
	// Message lists one message with exim -bp <id>. It returns ErrNotQueued
	// when exim does not hold a message with that ID.
	Message(id string) (QueueMessage, error)
	// Reason reads why the message is stuck from its msglog, with the last
	// lines of that log.
	Reason(id string) (StuckReason, []string, error)
	// Act runs one action on the message and returns the outcome the queue
	// shows afterwards. An error comes with OutcomeUnchanged.
	Act(action, id string) (string, error)
}

// eximNoSuchMessage is what exim -bp <id> prints below the message line when
// the message's spool header does not exist.
const eximNoSuchMessage = "*** spool read error: No such file or directory ***"

const (
	queueReadTimeout   = 10 * time.Second
	queueActionTimeout = 30 * time.Second
)

// EximQueueAdmin runs exim as transient units forked by PID 1 and reads
// msglogs under the exim spool root.
type EximQueueAdmin struct {
	spoolRoot string
	lookPath  systemdrun.LookPathFunc
	run       systemdrun.RunnerFunc
}

// NewEximQueueAdmin returns an admin for the exim queue under spoolRoot that
// resolves and runs commands through lookPath and run.
func NewEximQueueAdmin(spoolRoot string, lookPath systemdrun.LookPathFunc, run systemdrun.RunnerFunc) *EximQueueAdmin {
	return &EximQueueAdmin{spoolRoot: spoolRoot, lookPath: lookPath, run: run}
}

func (a *EximQueueAdmin) Message(id string) (QueueMessage, error) {
	if !ValidMessageID(id) {
		return QueueMessage{}, errors.New("invalid exim message id")
	}
	out, err := a.exim(systemdrun.Options{Pipe: true, RuntimeMax: queueReadTimeout}, queueReadTimeout, "-bp", id)
	// The reply, not the exit status, says the message is missing: exim
	// reports it on stdout whatever status it exits with.
	if bytes.HasSuffix(bytes.TrimSpace(out), []byte(eximNoSuchMessage)) {
		return QueueMessage{}, ErrNotQueued
	}
	if err != nil {
		return QueueMessage{}, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return QueueMessage{}, ErrNotQueued
	}
	m, err := ParseQueueDetail(out)
	if err != nil {
		return QueueMessage{}, err
	}
	if m.ID != id {
		return QueueMessage{}, ErrNotQueued
	}
	return m, nil
}

func (a *EximQueueAdmin) Reason(id string) (StuckReason, []string, error) {
	return ReadMsglogReason(a.spoolRoot, id)
}

// Act checks that the message is queued, runs the action and reads the
// queue again. As with FlushBackscatter, the queue decides the outcome:
// exim has exited non-zero for work it completed.
func (a *EximQueueAdmin) Act(action, id string) (string, error) {
	flag, ok := queueActionFlags[action]
	if !ok {
		return OutcomeUnchanged, fmt.Errorf("unknown queue action %q", action)
	}
	before, err := a.Message(id)
	if errors.Is(err, ErrNotQueued) {
		return OutcomeGone, nil
	}
	if err != nil {
		return OutcomeUnchanged, fmt.Errorf("read the message before acting: %w", err)
	}

	if action == "retry" {
		// A delivery attempt lasts as long as the receiving servers make it,
		// and stopping it midway can deliver the message twice. The unit
		// gets no runtime limit and nobody waits for it.
		if _, err = a.exim(systemdrun.Options{Required: true, NoWait: true}, queueActionTimeout, flag, id); err != nil {
			return OutcomeUnchanged, err
		}
		return OutcomeAttemptStarted, nil
	}

	out, runErr := a.exim(systemdrun.Options{Pipe: true, Required: true, RuntimeMax: queueActionTimeout}, queueActionTimeout, flag, id)
	if errors.Is(runErr, systemdrun.ErrUnavailable) {
		return OutcomeUnchanged, runErr
	}
	if runErr != nil {
		runErr = fmt.Errorf("exim %s: %w", flag, runErr)
		if text := boundText(string(out)); text != "" {
			runErr = fmt.Errorf("%w: %s", runErr, text)
		}
	}

	after, err := a.Message(id)
	switch {
	case errors.Is(err, ErrNotQueued) && action == "delete":
		return OutcomeRemoved, nil
	case errors.Is(err, ErrNotQueued) && action == "bounce":
		return OutcomeBounced, nil
	case errors.Is(err, ErrNotQueued):
		// Delivered or removed by someone else while it was being thawed.
		return OutcomeGone, nil
	case err != nil:
		return OutcomeUnchanged, errors.Join(runErr, fmt.Errorf("the outcome could not be read back: %w", err))
	case action == "thaw" && before.Frozen && !after.Frozen:
		return OutcomeThawed, nil
	}
	if runErr == nil {
		runErr = errors.New("exim left the message as it was")
	}
	return OutcomeUnchanged, runErr
}

func (a *EximQueueAdmin) exim(opt systemdrun.Options, timeout time.Duration, args ...string) ([]byte, error) {
	eximPath, err := a.lookPath("exim")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return systemdrun.Run(ctx, a.lookPath, a.run, opt, eximPath, args...)
}
