package learnwatch

import "bytes"

// Header parser bounds; exceeding either makes the message malformed.
const (
	MaxHeaderBytes  = 256 << 10
	MaxHeaderFields = 2048
)

// Verdict is the X-Spam-Status rule of spec 7.3.
type Verdict int

// Verdicts. Only VerdictEligible may become a report.
const (
	VerdictEligible Verdict = iota
	VerdictTagged
	VerdictMalformed
)

func (v Verdict) String() string {
	switch v {
	case VerdictEligible:
		return "eligible"
	case VerdictTagged:
		return "tagged"
	}
	return "malformed"
}

// ParseVerdict reads the bounded header block. Any X-Spam-Status that
// parses as Yes tags the message; every present one must parse as No for
// eligibility. Missing headers are eligible.
func ParseVerdict(snapshot []byte) Verdict {
	values, ok := spamStatuses(snapshot)
	if !ok {
		return VerdictMalformed
	}
	v := VerdictEligible
	for _, value := range values {
		switch spamToken(value) {
		case "yes":
			return VerdictTagged
		case "no":
		default:
			v = VerdictMalformed
		}
	}
	return v
}

// spamStatuses returns the unfolded X-Spam-Status values of the header
// block, or false for a header that breaks the syntax or the bounds.
// Whitespace-only lines continue the previous field, so a field that some
// parser might still read is never hidden behind one.
func spamStatuses(b []byte) ([][]byte, bool) {
	var values [][]byte
	fields, consumed := 0, 0
	inStatus := false
	for len(b) > 0 {
		line, rest, found := bytes.Cut(b, []byte{'\n'})
		consumed += len(line)
		if found {
			consumed++
		}
		if consumed > MaxHeaderBytes {
			return nil, false
		}
		b = rest
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) == 0 {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if fields == 0 {
				return nil, false
			}
			if inStatus {
				values[len(values)-1] = append(values[len(values)-1], line...)
			}
			continue
		}
		name, value, ok := bytes.Cut(line, []byte{':'})
		name = bytes.TrimRight(name, " \t")
		if !ok || !fieldName(name) {
			return nil, false
		}
		if fields++; fields > MaxHeaderFields {
			return nil, false
		}
		inStatus = asciiEqualFold(name, "x-spam-status")
		if inStatus {
			values = append(values, bytes.Clone(value))
		}
	}
	return values, true
}

// fieldName: printable ASCII without the colon (RFC 5322 ftext).
func fieldName(name []byte) bool {
	if len(name) == 0 {
		return false
	}
	for _, c := range name {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

// asciiEqualFold compares ASCII letters case-insensitively and nothing
// else, so Unicode folding cannot turn other bytes into a match.
func asciiEqualFold(b []byte, lower string) bool {
	if len(b) != len(lower) {
		return false
	}
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

// spamToken returns "yes" or "no" for a value that is exactly one of them
// after leading horizontal whitespace, followed by optional horizontal
// whitespace and a comma or the end; otherwise "".
func spamToken(v []byte) string {
	v = bytes.TrimLeft(v, " \t")
	for _, tok := range []string{"yes", "no"} {
		if len(v) < len(tok) || !asciiEqualFold(v[:len(tok)], tok) {
			continue
		}
		if rest := bytes.TrimLeft(v[len(tok):], " \t"); len(rest) == 0 || rest[0] == ',' {
			return tok
		}
	}
	return ""
}
