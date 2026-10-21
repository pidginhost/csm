package intel

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// StuckReason says why a queued message has not left: a class to filter and
// colour by, plain words for the operator, and the bounded error text it was
// read from.
type StuckReason struct {
	Class string `json:"class"`
	Text  string `json:"text"`
	Raw   string `json:"raw"`
}

const (
	// msglogTailBytes bounds the msglog read. Exim appends every delivery
	// attempt with the remote's reply, so the file grows for as long as the
	// message stays queued; the newest lines carry the current reason.
	msglogTailBytes = 8 << 10
	msglogTailLines = 20
)

// stuckClasses maps a keywordReason label to its queue reason class.
var stuckClasses = map[string]string{
	"rate_limit":     "rate_limited",
	"greylist":       "greylisted",
	"spamhaus":       "blocked",
	"blocked":        "blocked",
	"complaint":      "blocked",
	"mailbox_full":   "mailbox_full",
	"retry_wait":     "retry_wait",
	"host_not_found": "host_not_found",
	"refused":        "refused",
}

var stuckTexts = map[string]string{
	"rate_limited":   "rate limited",
	"mailbox_full":   "mailbox full",
	"refused":        "refused by the receiving server",
	"host_not_found": "receiving server not found or unreachable",
	"greylisted":     "greylisted",
	"blocked":        "blocked by the receiving server",
	"retry_wait":     "retry time not reached",
	"other":          "other",
}

var noAttemptReason = StuckReason{Class: "none", Text: "no delivery attempt logged yet"}

// ReadMsglogReason reads the tail of a queued message's exim msglog and says
// why the message is stuck, returning the last lines of that tail with it. A
// message without a msglog has had no delivery attempt yet. A msglog that is
// a symlink or not a regular file is refused with an error and never read.
func ReadMsglogReason(spoolRoot, id string) (StuckReason, []string, error) {
	if !ValidMessageID(id) {
		return StuckReason{}, nil, errors.New("invalid exim message id")
	}
	dir := filepath.Join(spoolRoot, "msglog")
	// With split_spool_directory exim files a message under the sixth ID
	// character; without it every msglog sits in one directory.
	for _, path := range []string{filepath.Join(dir, id[5:6], id), filepath.Join(dir, id)} {
		lines, err := readMsglogTail(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return noAttemptReason, nil, err
		}
		reason := msglogReason(lines)
		if len(lines) > msglogTailLines {
			lines = lines[len(lines)-msglogTailLines:]
		}
		return reason, lines, nil
	}
	return noAttemptReason, nil, nil
}

func readMsglogTail(path string) ([]string, error) {
	// #nosec G304 -- path joins the spool root with an ID that passed
	// ValidMessageID. O_NOFOLLOW refuses a planted symlink, O_NONBLOCK keeps a
	// fifo from blocking the open, and readFileTail refuses non-regular files.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readFileTail(f, msglogTailBytes)
}

// msglogReason picks the reason from the newest msglog line that carries one.
// The address-level deferral line can repeat only the host, so an unrecognized
// error yields to a recognized one logged just before it. With nothing
// recognized, the newest error line is reported as other.
func msglogReason(lines []string) StuckReason {
	var fallback string
	haveFallback := false
	for i := len(lines) - 1; i >= 0; i-- {
		msg := stripMsglogTime(lines[i])
		if info, ok := strings.CutPrefix(msg, "*** Frozen"); ok {
			if haveFallback {
				break // a newer attempt failed after the message was thawed
			}
			return frozenReason(info, lines[:i])
		}
		if !msglogErrorLine(msg) {
			continue
		}
		errText := msglogErrText(msg)
		if class, ok := stuckClasses[keywordReason(errText)]; ok {
			return StuckReason{Class: class, Text: stuckTexts[class], Raw: boundText(errText)}
		}
		if !haveFallback {
			fallback, haveFallback = errText, true
		}
	}
	if haveFallback {
		return StuckReason{Class: "other", Text: stuckTexts["other"], Raw: boundText(fallback)}
	}
	return noAttemptReason
}

// frozenReason reports a frozen message with the cause exim wrote after
// "*** Frozen" and the newest error logged before it.
func frozenReason(info string, older []string) StuckReason {
	info = strings.TrimSpace(info)
	if strings.HasPrefix(info, "(") && strings.HasSuffix(info, ")") {
		info = strings.TrimSpace(info[1 : len(info)-1])
	}
	r := StuckReason{Class: "frozen", Text: "frozen"}
	if info != "" {
		r.Text = boundText("frozen: " + info)
	}
	for i := len(older) - 1; i >= 0; i-- {
		if msg := stripMsglogTime(older[i]); msglogErrorLine(msg) {
			r.Raw = boundText(msglogErrText(msg))
			break
		}
	}
	return r
}

func stripMsglogTime(line string) string {
	n := len(eximTimeLayout)
	if len(line) > n && line[n] == ' ' {
		if _, err := time.Parse(eximTimeLayout, line[:n]); err == nil {
			return line[n+1:]
		}
	}
	return line
}

// msglogErrorLine reports whether a msglog line records a failed attempt: a
// host-level error, an address deferral or an error reply. The arrival line
// never counts because the sender chooses its subject.
func msglogErrorLine(msg string) bool {
	if strings.HasPrefix(msg, "Received from ") {
		return false
	}
	return strings.HasPrefix(msg, "H=") || strings.Contains(msg, " defer") ||
		strings.Contains(strings.ToLower(msg), "error")
}

// msglogErrText cuts a msglog line down to the error: from "SMTP error" when
// present, else from the deferral keyword, else the whole line. Cutting
// before the recipient keeps its address out of classification.
func msglogErrText(msg string) string {
	if i := strings.Index(msg, "SMTP error"); i >= 0 {
		return msg[i:]
	}
	if i := strings.Index(msg, " defer"); i >= 0 {
		return msg[i+1:]
	}
	return msg
}
