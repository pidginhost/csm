package intel

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/mail"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/pidginhost/csm/internal/systemdrun"
)

// QueueComposition is the makeup of the exim queue: how much is real mail still
// trying to deliver versus null-sender bounce backscatter, how much is frozen,
// and which recipients are stuck the most.
type QueueComposition struct {
	Total                int `json:"total"`
	Bounce               int `json:"bounce"` // null-sender <> messages (backscatter)
	Real                 int `json:"real"`
	Frozen               int `json:"frozen"`
	FlushableBackscatter int `json:"flushable_backscatter"` // frozen AND null-sender: safe to flush
	// OldestAgeSeconds is the age of the oldest queued message; left out
	// when the queue is empty.
	OldestAgeSeconds *int             `json:"oldest_age_seconds,omitempty"`
	TopRecipients    []RecipientCount `json:"top_recipients"`
}

// RecipientCount is a recipient address and how many queued messages target it.
type RecipientCount struct {
	Address string `json:"address"`
	Count   int    `json:"count"`
}

// QueueMessage is one message in the exim queue as `exim -bp` lists it.
type QueueMessage struct {
	ID         string    `json:"id"`
	Arrived    time.Time `json:"arrived"`
	AgeSeconds int       `json:"age_seconds"`
	// Size is in bytes, read back from the rounded size exim prints.
	Size      int64  `json:"size"`
	Sender    string `json:"sender"`     // without angle brackets; "" for a bounce
	LocalUser string `json:"local_user"` // the "(user)" marker, "" if absent
	Frozen    bool   `json:"frozen"`
	Bounce    bool   `json:"bounce"` // null sender <>
	// Recipients holds the first undelivered recipients: at most
	// maxQueueRecipients in a list, maxDetailRecipients in a detail.
	Recipients     []string `json:"recipients"`
	RecipientCount int      `json:"recipient_count"` // every undelivered recipient
	Delivered      int      `json:"delivered"`       // recipients exim marks D
}

const (
	topRecipientLimit   = 10
	maxQueueRecipients  = 50
	maxDetailRecipients = 1000
	// Queue headers are padded for age alignment. Recipient and continuation
	// lines are indented much deeper and must not be parsed as new messages.
	maxQueueHeaderIndent = 4
)

var (
	// A queue header line: "<age> <size> <msgid> <sender> [(login)] [*** frozen ***]",
	// where exim adds "(login)" when an untrusted caller set the sender. The
	// login is also accepted before the sender. Accept both the legacy 6-6-2
	// message id and the longer base62 form exim 4.97+ emits (6-11-4, e.g.
	// "1wVR8E-0000000C9po-1DDg").
	queueMsgIDRe = regexp.MustCompile(`^[0-9A-Za-z]{6}-(?:[0-9A-Za-z]{6}-[0-9A-Za-z]{2}|[0-9A-Za-z]{11}-[0-9A-Za-z]{4})$`)
	queueAgeRe   = regexp.MustCompile(`^\d+[smhdw]$`)
	queueSizeRe  = regexp.MustCompile(`(?i)^\d+(?:\.\d+)?[kmgt]?$`)
)

var queueSizeUnits = map[byte]float64{'k': 1 << 10, 'm': 1 << 20, 'g': 1 << 30, 't': 1 << 40}

// base62Digits is the alphabet exim encodes message IDs in.
const base62Digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var (
	eximLookPath = exec.LookPath
	eximRun      = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		// #nosec G204 -- name is either the resolved systemd-run path or Exim,
		// and args contain fixed flags plus validated Exim message IDs.
		return exec.CommandContext(ctx, name, args...).Output()
	}
)

// ValidMessageID reports whether id is an exim message ID in either format.
// It gates every ID that reaches exim argv or a spool path: the pattern is
// anchored and admits only base62 groups, so no leading dash, path separator
// or whitespace can pass.
func ValidMessageID(id string) bool {
	return queueMsgIDRe.MatchString(id)
}

// ArrivalFromID decodes the arrival time exim encodes in the first six
// characters of a message ID: seconds since the epoch in base 62. The legacy
// and the exim 4.97+ formats share that prefix.
func ArrivalFromID(id string) (time.Time, bool) {
	if !ValidMessageID(id) {
		return time.Time{}, false
	}
	var secs int64
	for i := 0; i < 6; i++ {
		secs = secs*62 + int64(strings.IndexByte(base62Digits, id[i]))
	}
	return time.Unix(secs, 0).UTC(), true
}

// ParseQueue parses `exim -bp` output into a composition summary. A spool
// header exim could not read is an error: the readable messages are not the
// whole queue.
func ParseQueue(out string) (QueueComposition, error) {
	comp := QueueComposition{TopRecipients: []RecipientCount{}}
	recipients := map[string]int{}
	oldestSeconds := -1

	msgs, err := parseQueueEntries(out, math.MaxInt)
	if err != nil {
		return comp, err
	}
	for _, m := range msgs {
		comp.Total++
		if m.Bounce {
			comp.Bounce++
		} else {
			comp.Real++
		}
		if m.Frozen {
			comp.Frozen++
		}
		if m.Bounce && m.Frozen {
			comp.FlushableBackscatter++
		}
		if m.AgeSeconds > oldestSeconds {
			oldestSeconds = m.AgeSeconds
			oldest := m.AgeSeconds
			comp.OldestAgeSeconds = &oldest
		}
		for _, addr := range m.Recipients {
			recipients[addr]++
		}
	}

	comp.TopRecipients = topRecipients(recipients)
	return comp, nil
}

// ParseQueueList parses `exim -bp` output into one entry per queued message,
// keeping the first maxQueueRecipients undelivered recipients of each. Output
// that holds text but no queue entry is an error, not an empty queue.
func ParseQueueList(out []byte) ([]QueueMessage, error) {
	return parseQueueMessages(out, maxQueueRecipients)
}

// ParseQueueDetail parses `exim -bp <id>` output for one message, keeping the
// first maxDetailRecipients undelivered recipients. Anything but exactly one
// message is an error.
func ParseQueueDetail(out []byte) (QueueMessage, error) {
	msgs, err := parseQueueMessages(out, maxDetailRecipients)
	if err != nil {
		return QueueMessage{}, err
	}
	if len(msgs) != 1 {
		return QueueMessage{}, fmt.Errorf("exim -bp listed %d messages, want 1", len(msgs))
	}
	return msgs[0], nil
}

func parseQueueMessages(out []byte, keep int) ([]QueueMessage, error) {
	text := string(out)
	msgs, err := parseQueueEntries(text, keep)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		if strings.TrimSpace(text) != "" {
			return nil, errors.New("exim -bp output holds no queue entry")
		}
		return []QueueMessage{}, nil
	}
	for i := range msgs {
		m := &msgs[i]
		m.Arrived, _ = ArrivalFromID(m.ID)
		if m.Recipients == nil {
			m.Recipients = []string{}
		}
	}
	return msgs, nil
}

// errSpoolUnreadable means exim listed a message whose spool header it could
// not read.
var errSpoolUnreadable = errors.New("exim -bp could not read a spool header")

// parseQueueEntries walks `exim -bp` output into messages, keeping the first
// keep undelivered recipients of each and counting all of them. Recipient
// lines are indented deeper than headers; any other line ends the current
// message so stray text cannot attach to it.
func parseQueueEntries(out string, keep int) ([]QueueMessage, error) {
	var msgs []QueueMessage
	current := -1

	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		// Exim may exit successfully while some spool headers cannot be
		// read. Do not present the readable subset as the whole queue.
		// A missing file can instead mean delivery raced the listing.
		if strings.HasPrefix(trimmed, "*** spool read error:") && trimmed != eximNoSuchMessage {
			return nil, errSpoolUnreadable
		}
		if m, ok := parseQueueHeader(line); ok {
			msgs = append(msgs, m)
			current = len(msgs) - 1
			continue
		}

		if current < 0 {
			continue
		}
		if trimmed == "" {
			continue
		}
		if queueHeaderCandidate(line) || queueHeaderIndent(line) <= maxQueueHeaderIndent || !queueRecipientLine(line) {
			current = -1
			continue
		}
		m := &msgs[current]
		// Exim prefixes an already-delivered recipient with "D"; it is not stuck.
		if addr, delivered := strings.CutPrefix(trimmed, "D "); delivered {
			if _, ok := queueRecipientAddress(strings.TrimSpace(addr)); ok {
				m.Delivered++
			}
			continue
		}
		if addr, ok := queueRecipientAddress(trimmed); ok {
			m.RecipientCount++
			if len(m.Recipients) < keep {
				m.Recipients = append(m.Recipients, addr)
			}
		}
	}
	return msgs, nil
}

func parseQueueHeader(line string) (QueueMessage, bool) {
	if queueHeaderIndent(line) > maxQueueHeaderIndent {
		return QueueMessage{}, false
	}
	age, rest := cutQueueField(line)
	size, rest := cutQueueField(rest)
	id, rest := cutQueueField(rest)
	if !queueAgeRe.MatchString(age) || !queueSizeRe.MatchString(size) || !queueMsgIDRe.MatchString(id) {
		return QueueMessage{}, false
	}
	m := QueueMessage{ID: id, AgeSeconds: AgeToSeconds(age), Size: queueSizeBytes(size)}

	rest = strings.TrimSpace(rest)
	if field, after := cutQueueField(rest); queueLocalUserField(field) {
		m.LocalUser = field[1 : len(field)-1]
		rest = strings.TrimSpace(after)
	}
	var sender string
	if strings.HasPrefix(rest, "<") {
		// The sender may quote spaces or ">" in its local part. Exim's own
		// markers after it never contain ">", so the last one closes it.
		end := strings.LastIndexByte(rest, '>')
		if end < 0 {
			return QueueMessage{}, false
		}
		sender, rest = rest[1:end], rest[end+1:]
		m.Bounce = sender == ""
	} else {
		sender, rest = cutQueueField(rest)
		if sender == "" {
			return QueueMessage{}, false
		}
	}
	m.Sender = sender

	marks := strings.Fields(rest)
	if len(marks) > 0 && m.LocalUser == "" && queueLocalUserField(marks[0]) {
		m.LocalUser = marks[0][1 : len(marks[0])-1]
		marks = marks[1:]
	}
	if len(marks) == 3 && marks[0] == "***" && marks[1] == "frozen" && marks[2] == "***" {
		m.Frozen = true
		marks = nil
	}
	if len(marks) != 0 {
		return QueueMessage{}, false
	}
	return m, true
}

// cutQueueField returns the first whitespace-separated field of s and the
// text after it.
func cutQueueField(s string) (field, rest string) {
	s = strings.TrimLeftFunc(s, unicode.IsSpace)
	if i := strings.IndexFunc(s, unicode.IsSpace); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

// queueSizeBytes converts a size token that matched queueSizeRe ("800",
// "2.9K", "1.2M") to bytes. Exim rounds what it prints, so the result is the
// size the token shows, not the exact spool size.
func queueSizeBytes(token string) int64 {
	token = strings.ToLower(token)
	unit := 1.0
	if u, ok := queueSizeUnits[token[len(token)-1]]; ok {
		unit = u
		token = token[:len(token)-1]
	}
	// The token matched queueSizeRe, so the only possible error is a range
	// overflow, which returns +Inf and is clamped below.
	n, _ := strconv.ParseFloat(token, 64)
	// float64(math.MaxInt64) rounds up to 2^63, which int64 cannot hold.
	if size := n * unit; size < math.MaxInt64 {
		return int64(size)
	}
	return math.MaxInt64
}

func queueHeaderCandidate(line string) bool {
	if queueHeaderIndent(line) > maxQueueHeaderIndent {
		return false
	}
	fields := strings.Fields(line)
	return (len(fields) == 4 || len(fields) == 7) && queueMsgIDRe.MatchString(fields[2])
}

func queueRecipientLine(line string) bool {
	return len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
}

func queueRecipientAddress(trimmed string) (string, bool) {
	addr := trimmed
	if strings.HasPrefix(addr, "<") && strings.HasSuffix(addr, ">") {
		addr = addr[1 : len(addr)-1]
	}
	if len(addr) > maxAddressLen || !strings.Contains(addr, "@") {
		return "", false
	}
	if parsed, err := mail.ParseAddress(addr); err != nil || parsed.Name != "" {
		return "", false
	}
	return addr, true
}

func queueLocalUserField(field string) bool {
	if len(field) < 3 || field[0] != '(' || field[len(field)-1] != ')' {
		return false
	}
	return !strings.ContainsAny(field[1:len(field)-1], "() \t\r\n")
}

func queueHeaderIndent(line string) int {
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case ' ':
			continue
		case '\t':
			return maxQueueHeaderIndent + 1
		default:
			return i
		}
	}
	return len(line)
}

// AgeToSeconds converts an exim age token (e.g. "25m", "4d") to seconds. An
// unrecognized token returns 0.
func AgeToSeconds(age string) int {
	if len(age) < 2 {
		return 0
	}
	n, err := strconv.Atoi(age[:len(age)-1])
	if err != nil {
		return 0
	}
	switch age[len(age)-1] {
	case 's':
		return n
	case 'm':
		return n * 60
	case 'h':
		return n * 3600
	case 'd':
		return n * 86400
	case 'w':
		return n * 604800
	}
	return 0
}

func topRecipients(m map[string]int) []RecipientCount {
	out := make([]RecipientCount, 0, len(m))
	for addr, n := range m {
		out = append(out, RecipientCount{Address: addr, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Address < out[j].Address
	})
	if len(out) > topRecipientLimit {
		out = out[:topRecipientLimit]
	}
	return out
}

// QueueReporter produces the queue composition for the host.
type QueueReporter interface {
	Composition() (QueueComposition, error)
}

// EmptyQueueReporter yields an empty composition. It stands in on platforms
// with no exim queue (non-cPanel).
type EmptyQueueReporter struct{}

func (EmptyQueueReporter) Composition() (QueueComposition, error) {
	return QueueComposition{TopRecipients: []RecipientCount{}}, nil
}

// EximQueueSource runs `exim -bp` and parses the result.
type EximQueueSource struct {
	run func() ([]byte, error)
}

// NewEximQueueSource returns a source that reads the live exim queue.
func NewEximQueueSource() *EximQueueSource {
	return &EximQueueSource{run: runEximBp}
}

// Composition lists the queue and summarizes it. An exim error yields an empty
// composition, not a hard error: this is a read-only visibility surface. A
// listing that could not read every spool header is an error.
func (s *EximQueueSource) Composition() (QueueComposition, error) {
	out, err := s.run()
	if err != nil {
		// exim absent or failing means no observable queue, not an API error;
		// surface an empty composition rather than a 500.
		return QueueComposition{TopRecipients: []RecipientCount{}}, nil //nolint:nilerr
	}
	return ParseQueue(string(out))
}

func runEximBp() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return runEximCommand(ctx, 10*time.Second, "-bp")
}

func runEximCommand(ctx context.Context, runtimeMax time.Duration, args ...string) ([]byte, error) {
	eximPath, err := eximLookPath("exim")
	if err != nil {
		return nil, err
	}
	return systemdrun.Run(ctx, eximLookPath, eximRun, systemdrun.Options{
		Pipe:       true,
		RuntimeMax: runtimeMax,
	}, eximPath, args...)
}
