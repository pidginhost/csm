package emailspool

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// ExtractDomain returns the lowercased, IDN-normalised domain portion of an
// RFC 5322 address or display-name form. Returns "" on parse failure.
//
// Quoted local parts ("a@b"@example.com) are handled by treating the address
// as the substring after the LAST unquoted '@'.
func ExtractDomain(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.LastIndex(s, "<"); i >= 0 {
		if j := strings.LastIndex(s, ">"); j > i {
			s = s[i+1 : j]
		}
	}
	at := lastUnquotedAt(s)
	if at < 0 {
		return ""
	}
	domain := strings.TrimSpace(s[at+1:])
	domain = strings.ToLower(domain)
	if ascii, err := idna.ToASCII(domain); err == nil {
		domain = ascii
	}
	return domain
}

// lastUnquotedAt returns the index of the rightmost '@' character that is not
// inside a double-quoted segment, or -1 if none.
func lastUnquotedAt(s string) int {
	inQuote := false
	last := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			i++ // skip the next byte (quoted-pair)
		case '"':
			inQuote = !inQuote
		case '@':
			if !inQuote {
				last = i
			}
		}
	}
	return last
}

// IsSubdomainOrEqual reports whether candidate is base or a subdomain of base.
// Both inputs are case-insensitive. Empty inputs return false.
func IsSubdomainOrEqual(candidate, base string) bool {
	if candidate == "" || base == "" {
		return false
	}
	c := strings.ToLower(strings.TrimSuffix(candidate, "."))
	b := strings.ToLower(strings.TrimSuffix(base, "."))
	if c == b {
		return true
	}
	return strings.HasSuffix(c, "."+b)
}

// MaxSpoolHeaderBytes bounds how much of an Exim -H file we read.
// 32 KiB covers rich messages with DKIM, ARC, and folded MIME headers
// without unbounded memory.
const MaxSpoolHeaderBytes = 32 * 1024

// Headers is the parsed envelope + interesting RFC 5322 fields from a
// cPanel-Exim spool -H file. EnvelopeUser comes from the file's line 2
// (the local UID under which Exim accepted the message); the RFC 5322
// fields come from the message's mail headers section. Empty string means
// "header absent" -- callers should not synthesise defaults from absence.
type Headers struct {
	EnvelopeUser string
	EnvelopeUID  int
	From         string
	ReplyTo      string
	Subject      string
	XPHPScript   string
	XMailer      string
	UserAgent    string
	MessageID    string
	// Recipients holds the envelope recipient addresses when the Exim -H
	// recipient block can be unambiguously located; empty when the block is
	// absent or its shape cannot be validated. Consumers that gate on
	// recipient diversity must treat empty as "unknown" and fail open.
	Recipients []string
}

// ParseHeaders reads the given Exim -H file and returns a Headers.
// Returns the parse error if the file cannot be opened or is structurally
// invalid; otherwise missing individual headers leave the corresponding
// Headers field empty.
func ParseHeaders(path string) (Headers, error) {
	// #nosec G304 -- path is supplied by the daemon's Exim spool
	// watcher and resolved from /var/spool/exim/input/, an
	// operator-trusted directory enumerated by the spool walker.
	f, err := os.Open(path)
	if err != nil {
		return Headers{}, err
	}
	defer f.Close()
	h, err := ParseHeadersReader(f)
	if err != nil {
		return Headers{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return h, nil
}

// ParseHeadersReader is the io.Reader form of ParseHeaders for callers that
// already have the spool bytes in memory or behind a custom seam (e.g. the
// checks package's osFS abstraction). It applies the same Exim -H parsing
// rules as ParseHeaders -- envelope preamble, blank-line separator,
// "NNNX " prefixed RFC 5322 headers -- and is bounded by MaxSpoolHeaderBytes
// per token; oversize input returns bufio.ErrTooLong.
func ParseHeadersReader(r io.Reader) (Headers, error) {
	var h Headers
	// Per-line memory is bounded by the scanner's max buffer
	// (MaxSpoolHeaderBytes); a token larger than that returns
	// bufio.ErrTooLong. We deliberately do NOT wrap r in an io.LimitReader:
	// when LimitReader returns EOF mid-token, bufio.Scanner emits the
	// partial token without error and oversize spool files are silently
	// truncated. That hides the failure from operators.
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 8192), MaxSpoolHeaderBytes)

	// Line 1: msgID-H (we ignore the value; presence is enough)
	if !sc.Scan() {
		return Headers{}, errors.New("empty spool file")
	}

	// Line 2: "<user> <uid> <gid>"
	if !sc.Scan() {
		return Headers{}, errors.New("missing envelope user line")
	}
	fields := splitFields(sc.Text())
	if len(fields) < 2 {
		return Headers{}, fmt.Errorf("malformed envelope user line: %q", sc.Text())
	}
	h.EnvelopeUser = fields[0]
	if uid, err := strconv.Atoi(fields[1]); err == nil {
		h.EnvelopeUID = uid
	}

	// Skip remaining envelope metadata until the blank line that separates
	// it from the RFC 5322 header section. Exim's -H format places mail
	// headers AFTER a blank line that follows the recipient list; recipients
	// are preceded by a numeric count line.
	inHeaders := false
	var preamble []string
	lastHeader := ""
	skippingDeleted := false
	for sc.Scan() {
		line := sc.Text()
		if !inHeaders {
			if line == "" {
				inHeaders = true
				continue
			}
			preamble = append(preamble, line)
			continue
		}
		// RFC 5322 header section. Each header line in Exim's -H format
		// starts with "<count><flag> <name>: <value>" where count is a
		// variable-width decimal byte count for the full stored header
		// (including folded continuation lines) and flag is a single Exim
		// marker ('T', 'F', 'R', '*', space, etc.).
		if isFoldedHeaderLine(line) {
			if !skippingDeleted && lastHeader != "" {
				appendEximHeaderContinuation(&h, lastHeader, line)
			}
			continue
		}
		lastHeader = ""
		skippingDeleted = false
		name, value, deleted, ok := parseEximHeaderLine(line)
		if deleted {
			skippingDeleted = true
			continue
		}
		if !ok {
			continue
		}
		if canonical, handled := setEximHeaderValue(&h, name, value); handled {
			lastHeader = canonical
		}
	}
	if err := sc.Err(); err != nil {
		return Headers{}, fmt.Errorf("scan spool: %w", err)
	}
	if !inHeaders {
		return Headers{}, errors.New("missing header section separator")
	}
	h.Recipients = extractEximRecipients(preamble)
	return h, nil
}

// extractEximRecipients recovers the envelope recipient addresses from the
// Exim -H preamble (the lines between the envelope-user line and the blank
// header separator). Exim writes the recipient block last: a line holding only
// the recipient count N, then exactly N recipient lines that run to the end of
// the preamble. Anchoring on "index + 1 + N == len(preamble)" plus an
// address-shape check on every claimed recipient locates the block without a
// full grammar and tolerates option/ACL lines above it. Any ambiguity, including
// a malformed anchored candidate, returns nil so callers treat recipients as
// unknown and fail open.
func extractEximRecipients(preamble []string) []string {
	var candidate []string
	ambiguous := false
	for i, line := range preamble {
		n, ok := parseBareUint(line)
		if !ok || n < 1 || i+1+n != len(preamble) {
			continue
		}
		rcpts := make([]string, 0, n)
		valid := true
		for _, r := range preamble[i+1:] {
			addr := firstField(r)
			if addr == "" || !strings.Contains(addr, "@") {
				valid = false
				break
			}
			rcpts = append(rcpts, addr)
		}
		if !valid {
			ambiguous = true
			continue
		}
		if candidate != nil {
			ambiguous = true
			continue
		}
		candidate = rcpts
	}
	if ambiguous {
		return nil
	}
	return candidate
}

// parseBareUint reports whether s is a single non-negative integer token with
// no other characters. The length cap rejects timestamps and other long
// numeric option values that are not recipient counts.
func parseBareUint(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 9 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

func firstField(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		s = s[:i]
	}
	return s
}

// parseEximHeaderLine returns the header name, value, deletion marker, and
// prefix-valid marker for an Exim -H header line of the form
// "NNNF Header-Name: value". The prefix is a variable-width decimal length
// (Exim writes the byte count of the full stored header, including folded
// continuation lines), followed by a flag byte ('T', 'F', 'R', '*', space,
// etc.) and a space separator; the whole prefix is stripped before splitting
// on the colon.
func parseEximHeaderLine(line string) (name string, value string, deleted bool, ok bool) {
	i := 0
	for i < len(line) && isDigit(line[i]) {
		i++
	}
	if i == 0 || i+1 >= len(line) {
		return "", "", false, false
	}
	// After the digit run: a flag byte (letter, or space for unflagged
	// headers such as X-PHP-Script in real cPanel-Exim spool output) then a
	// single space separator.
	if !isEximHeaderFlag(line[i]) || line[i+1] != ' ' {
		return "", "", false, false
	}
	if line[i] == '*' {
		return "", "", true, true
	}
	rest := line[i+2:]
	colon := indexByte(rest, ':')
	if colon < 0 {
		return "", "", false, true
	}
	name = rest[:colon]
	if colon+1 < len(rest) {
		value = trimLeadingSpace(rest[colon+1:])
	}
	return name, value, false, true
}

func isFoldedHeaderLine(line string) bool {
	return len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
}

func isEximHeaderFlag(b byte) bool {
	return b == ' ' || b == '*' || isLetter(b)
}

func setEximHeaderValue(h *Headers, name, value string) (string, bool) {
	switch strings.ToLower(name) {
	case "from":
		h.From = value
		return "from", true
	case "reply-to":
		h.ReplyTo = value
		return "reply-to", true
	case "subject":
		h.Subject = value
		return "subject", true
	case "x-php-script":
		h.XPHPScript = value
		return "x-php-script", true
	case "x-mailer":
		h.XMailer = value
		return "x-mailer", true
	case "user-agent":
		h.UserAgent = value
		return "user-agent", true
	case "message-id":
		h.MessageID = value
		return "message-id", true
	default:
		return "", false
	}
}

func appendEximHeaderContinuation(h *Headers, name, line string) {
	value := trimLeadingSpace(line)
	switch name {
	case "from":
		h.From = appendFoldedHeaderValue(h.From, value)
	case "reply-to":
		h.ReplyTo = appendFoldedHeaderValue(h.ReplyTo, value)
	case "subject":
		h.Subject = appendFoldedHeaderValue(h.Subject, value)
	case "x-php-script":
		h.XPHPScript = appendFoldedHeaderValue(h.XPHPScript, value)
	case "x-mailer":
		h.XMailer = appendFoldedHeaderValue(h.XMailer, value)
	case "user-agent":
		h.UserAgent = appendFoldedHeaderValue(h.UserAgent, value)
	case "message-id":
		h.MessageID = appendFoldedHeaderValue(h.MessageID, value)
	}
}

func appendFoldedHeaderValue(current, continuation string) string {
	if current == "" {
		return continuation
	}
	if continuation == "" {
		return current
	}
	return current + " " + continuation
}

func isDigit(b byte) bool  { return b >= '0' && b <= '9' }
func isLetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
func trimLeadingSpace(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return s[i:]
}
func splitFields(s string) []string {
	var out []string
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}
