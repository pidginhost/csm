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
	MessageID    string
}

// ParseHeaders reads the given Exim -H file and returns a Headers.
// Returns the parse error if the file cannot be opened or is structurally
// invalid; otherwise missing individual headers leave the corresponding
// Headers field empty.
func ParseHeaders(path string) (Headers, error) {
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
	for sc.Scan() {
		line := sc.Text()
		if !inHeaders {
			if line == "" {
				inHeaders = true
			}
			continue
		}
		// RFC 5322 header section. Each header line in Exim's -H format
		// starts with "<count><flag> <name>: <value>" where count is 3-4
		// digits and flag is a single ASCII letter ('T', 'F', 'R', etc.).
		// Folded continuations start with whitespace.
		name, value := parseEximHeaderLine(line)
		switch name {
		case "From":
			h.From = value
		case "Reply-To":
			h.ReplyTo = value
		case "Subject":
			h.Subject = value
		case "X-PHP-Script":
			h.XPHPScript = value
		case "X-Mailer":
			h.XMailer = value
		case "Message-ID":
			h.MessageID = value
		}
	}
	if err := sc.Err(); err != nil {
		return Headers{}, fmt.Errorf("scan spool: %w", err)
	}
	if !inHeaders {
		return Headers{}, errors.New("missing header section separator")
	}
	return h, nil
}

// parseEximHeaderLine returns (header-name, header-value) for an Exim -H
// header line of the form "NNNF Header-Name: value", or ("", "") if the
// line cannot be parsed (folded continuations, garbage). The 4-byte prefix
// is 3 digits + flag byte (a single ASCII letter such as 'T', 'F', 'R', or
// a space when the header has no flag) followed by a space separator; it
// is stripped before splitting on the colon.
func parseEximHeaderLine(line string) (string, string) {
	if len(line) < 5 {
		return "", ""
	}
	// Position 3 is space for unflagged Exim headers (e.g. X-PHP-Script
	// in real cPanel-Exim spool output) and a flag letter (T/F/R/I/...)
	// for flagged headers. Both shapes appear; the parser captures both.
	if !isDigit(line[0]) || !isDigit(line[1]) || !isDigit(line[2]) {
		return "", ""
	}
	if !isLetter(line[3]) && line[3] != ' ' || line[4] != ' ' {
		return "", ""
	}
	rest := line[5:]
	colon := indexByte(rest, ':')
	if colon < 0 {
		return "", ""
	}
	name := rest[:colon]
	value := ""
	if colon+1 < len(rest) {
		value = trimLeadingSpace(rest[colon+1:])
	}
	return name, value
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
