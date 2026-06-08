package intel

import (
	"context"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// QueueComposition is the makeup of the exim queue: how much is real mail still
// trying to deliver versus null-sender bounce backscatter, how much is frozen,
// and which recipients are stuck the most.
type QueueComposition struct {
	Total                int              `json:"total"`
	Bounce               int              `json:"bounce"` // null-sender <> messages (backscatter)
	Real                 int              `json:"real"`
	Frozen               int              `json:"frozen"`
	FlushableBackscatter int              `json:"flushable_backscatter"` // frozen AND null-sender: safe to flush
	OldestAge            string           `json:"oldest_age"`
	TopRecipients        []RecipientCount `json:"top_recipients"`
}

// RecipientCount is a recipient address and how many queued messages target it.
type RecipientCount struct {
	Address string `json:"address"`
	Count   int    `json:"count"`
}

const (
	topRecipientLimit = 10
	// Queue headers are padded for age alignment. Recipient and continuation
	// lines are indented much deeper and must not be parsed as new messages.
	maxQueueHeaderIndent = 4
)

var (
	// A queue header line: "<age> <size> <msgid> [(user)] <sender> [*** frozen ***]".
	// Accept both the legacy 6-6-2 message id and the longer base62 form exim
	// 4.97+ emits (6-11-4, e.g. "1wVR8E-0000000C9po-1DDg").
	queueMsgIDRe = regexp.MustCompile(`^[0-9A-Za-z]{6}-(?:[0-9A-Za-z]{6}-[0-9A-Za-z]{2}|[0-9A-Za-z]{11}-[0-9A-Za-z]{4})$`)
	queueAgeRe   = regexp.MustCompile(`^\d+[smhdw]$`)
	queueSizeRe  = regexp.MustCompile(`(?i)^\d+(?:\.\d+)?[kmgt]?$`)
)

// ParseQueue parses `exim -bp` output into a composition summary.
func ParseQueue(out string) QueueComposition {
	comp := QueueComposition{TopRecipients: []RecipientCount{}}
	recipients := map[string]int{}
	oldestSeconds := -1
	inMessage := false

	for _, line := range strings.Split(out, "\n") {
		if _, age, ageSec, bounce, frozen, ok := parseQueueHeader(line); ok {
			comp.Total++
			if bounce {
				comp.Bounce++
			} else {
				comp.Real++
			}
			if frozen {
				comp.Frozen++
			}
			if bounce && frozen {
				comp.FlushableBackscatter++
			}
			if ageSec > oldestSeconds {
				oldestSeconds = ageSec
				comp.OldestAge = age
			}
			inMessage = true
			continue
		}

		if !inMessage {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if queueHeaderCandidate(line) {
			inMessage = false
			continue
		}
		if queueHeaderIndent(line) <= maxQueueHeaderIndent {
			inMessage = false
			continue
		}
		if !queueRecipientLine(line) {
			inMessage = false
			continue
		}
		if addr, ok := queueRecipientAddress(trimmed); ok {
			recipients[addr]++
		}
	}

	comp.TopRecipients = topRecipients(recipients)
	return comp
}

func parseQueueHeader(line string) (msgID, age string, ageSeconds int, bounce, frozen, ok bool) {
	if queueHeaderIndent(line) > maxQueueHeaderIndent {
		return "", "", 0, false, false, false
	}
	fields := strings.Fields(line)
	if len(fields) != 4 && len(fields) != 5 && len(fields) != 7 && len(fields) != 8 {
		return "", "", 0, false, false, false
	}
	if !queueAgeRe.MatchString(fields[0]) || !queueSizeRe.MatchString(fields[1]) || !queueMsgIDRe.MatchString(fields[2]) {
		return "", "", 0, false, false, false
	}
	senderIndex := 3
	frozenIndex := 4
	if len(fields) == 5 || len(fields) == 8 {
		if !queueLocalUserField(fields[3]) {
			return "", "", 0, false, false, false
		}
		senderIndex = 4
		frozenIndex = 5
	}
	if len(fields) == 7 || len(fields) == 8 {
		if fields[frozenIndex] != "***" || fields[frozenIndex+1] != "frozen" || fields[frozenIndex+2] != "***" {
			return "", "", 0, false, false, false
		}
		frozen = true
	}
	bounce = fields[senderIndex] == "<>"
	return fields[2], fields[0], ageToSeconds(fields[0]), bounce, frozen, true
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
	fields := strings.Fields(trimmed)
	// Exim prefixes an already-delivered recipient with "D"; it is not stuck.
	if len(fields) == 2 && fields[0] == "D" {
		return "", false
	}
	if len(fields) != 1 {
		return "", false
	}
	addr := strings.Trim(fields[0], "<>")
	if len(addr) > maxAddressLen || !strings.Contains(addr, "@") {
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

// ageToSeconds converts an exim age token (e.g. "25m", "4d") to seconds. An
// unrecognized token returns 0.
func ageToSeconds(age string) int {
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
// composition, not a hard error: this is a read-only visibility surface.
func (s *EximQueueSource) Composition() (QueueComposition, error) {
	out, err := s.run()
	if err != nil {
		// exim absent or failing means no observable queue, not an API error;
		// surface an empty composition rather than a 500.
		return QueueComposition{TopRecipients: []RecipientCount{}}, nil //nolint:nilerr
	}
	return ParseQueue(string(out)), nil
}

func runEximBp() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "exim", "-bp").Output()
}
