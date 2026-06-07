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
	Total         int              `json:"total"`
	Bounce        int              `json:"bounce"` // null-sender <> messages (backscatter)
	Real          int              `json:"real"`
	Frozen        int              `json:"frozen"`
	OldestAge     string           `json:"oldest_age"`
	TopRecipients []RecipientCount `json:"top_recipients"`
}

// RecipientCount is a recipient address and how many queued messages target it.
type RecipientCount struct {
	Address string `json:"address"`
	Count   int    `json:"count"`
}

const topRecipientLimit = 10

var (
	// A queue header line: "<age> <size> <msgid> <sender> [*** frozen ***]".
	queueMsgIDRe = regexp.MustCompile(`^[0-9A-Za-z]{6}-[0-9A-Za-z]{6}-[0-9A-Za-z]{2}$`)
	queueAgeRe   = regexp.MustCompile(`^\d+[smhdw]$`)
)

// ParseQueue parses `exim -bp` output into a composition summary.
func ParseQueue(out string) QueueComposition {
	comp := QueueComposition{TopRecipients: []RecipientCount{}}
	recipients := map[string]int{}
	oldestSeconds := -1
	inMessage := false

	for _, line := range strings.Split(out, "\n") {
		if age, ageSec, bounce, frozen, ok := parseQueueHeader(line); ok {
			comp.Total++
			if bounce {
				comp.Bounce++
			} else {
				comp.Real++
			}
			if frozen {
				comp.Frozen++
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
		addr := strings.TrimSpace(line)
		if addr == "" {
			continue
		}
		// Exim prefixes an already-delivered recipient with "D"; it is not stuck.
		if strings.HasPrefix(addr, "D ") {
			continue
		}
		if strings.Contains(addr, "@") {
			recipients[addr]++
		}
	}

	comp.TopRecipients = topRecipients(recipients)
	return comp
}

func parseQueueHeader(line string) (age string, ageSeconds int, bounce, frozen, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return "", 0, false, false, false
	}
	if !queueAgeRe.MatchString(fields[0]) || !queueMsgIDRe.MatchString(fields[2]) {
		return "", 0, false, false, false
	}
	bounce = fields[3] == "<>"
	frozen = strings.Contains(line, "*** frozen ***")
	return fields[0], ageToSeconds(fields[0]), bounce, frozen, true
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
