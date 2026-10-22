// Package quarantine is the CSM-owned Maildir that holds external forward
// copies the forward-guard decided to withhold. The exim transport (Phase 2
// Slice C) appends held copies here with X-CSM-* control headers; CSM lists
// them, releases (re-injects to the original external recipient) or deletes,
// and prunes by age. CSM is never in the live delivery path -- exim writes the
// file, CSM only acts on it afterwards.
package quarantine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
)

// Control headers the exim transport adds and CSM parses. They are stripped
// before a message is re-injected so they never leak to the recipient.
const (
	hdrForwarder = "X-CSM-Forwarder"
	hdrRecipient = "X-CSM-Recipient"
	hdrSender    = "X-CSM-Sender"
	hdrReasons   = "X-CSM-Reasons"
	hdrPrefix    = "X-CSM-"
)

// HeldMessage is the operator-facing view of one held forward copy.
type HeldMessage struct {
	ID        string    `json:"id"`
	Forwarder string    `json:"forwarder"` // local source address that forwarded
	Recipient string    `json:"recipient"` // external destination that was held
	Sender    string    `json:"sender"`    // envelope sender ("" = null-sender bounce)
	Reasons   []string  `json:"reasons"`
	Subject   string    `json:"subject"`
	HeldAt    time.Time `json:"held_at"`
	Size      int64     `json:"size"`
}

// Quarantine manages the held-forward Maildir.
type Quarantine struct {
	base     string
	counter  atomic.Uint64
	sendmail func(sender, recipient string, body []byte) error
}

// New returns a quarantine rooted at dir (a Maildir; new/cur/tmp are created on
// demand). The default re-injector shells out to the platform sendmail.
func New(dir string) *Quarantine {
	return &Quarantine{base: dir, sendmail: runSendmail}
}

func (q *Quarantine) sub(name string) string { return filepath.Join(q.base, name) }

// Hold writes a held copy into the Maildir with the X-CSM-* control headers and
// returns its id (the Maildir filename). In production exim's appendfile writes
// these files; Hold produces the same layout for CSM-side paths and tests: the
// control headers follow the message's own header fields, as exim's
// headers_add appends them.
func (q *Quarantine) Hold(m HeldMessage, body []byte) (string, error) {
	for _, d := range []string{"tmp", "new", "cur"} {
		if err := os.MkdirAll(q.sub(d), 0700); err != nil {
			return "", fmt.Errorf("creating maildir %s: %w", d, err)
		}
	}

	// cut is where the header fields end: the start of the blank separator
	// line, or the end of a message that has none.
	cut := headerBlockEnd(body)
	if start := bytes.LastIndexByte(body[:max(cut-1, 0)], '\n') + 1; cut > 0 && isBlankLine(body[start:cut]) {
		cut = start
	}
	var buf bytes.Buffer
	buf.Write(body[:cut])
	if cut > 0 && body[cut-1] != '\n' {
		buf.WriteString("\r\n")
	}
	fmt.Fprintf(&buf, "%s: %s\r\n", hdrForwarder, headerValue(m.Forwarder))
	fmt.Fprintf(&buf, "%s: %s\r\n", hdrRecipient, headerValue(m.Recipient))
	fmt.Fprintf(&buf, "%s: %s\r\n", hdrSender, headerValue(m.Sender))
	fmt.Fprintf(&buf, "%s: %s\r\n", hdrReasons, headerValue(strings.Join(m.Reasons, ",")))
	buf.Write(body[cut:])

	id := fmt.Sprintf("%d.%d.csm", time.Now().UnixNano(), q.counter.Add(1))
	tmp := filepath.Join(q.sub("tmp"), id)
	if err := os.WriteFile(tmp, buf.Bytes(), 0600); err != nil { // #nosec G306 -- 0600 is intended
		return "", fmt.Errorf("writing held message: %w", err)
	}
	dst := filepath.Join(q.sub("new"), id)
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("committing held message: %w", err)
	}
	return id, nil
}

// List returns every held message with parsed metadata. A missing Maildir is
// not an error: it just means nothing has been held.
func (q *Quarantine) List() ([]HeldMessage, error) {
	out := []HeldMessage{}
	for _, dir := range []string{"new", "cur"} {
		entries, err := os.ReadDir(q.sub(dir))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			m, err := q.read(dir, e.Name())
			if err != nil {
				continue // skip unreadable/partial entries rather than fail the whole list
			}
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HeldAt.Before(out[j].HeldAt) })
	return out, nil
}

// maxHeaderBlock bounds the header block CSM reads from a held copy: exim's
// default header_maxsize (1 MiB) for the message's own fields, plus room for
// the control headers the transport appends after them. maxSubjectLen bounds
// the subject the list shows.
const (
	maxHeaderBlock = 1<<20 + 8<<10
	maxSubjectLen  = 160
)

var errHeaderBlockTooLarge = errors.New("held message header block is larger than CSM reads")

// readHeaderBlock reads lines up to and including the first blank line, or
// to the end of a message with no body. A longer block than maxHeaderBlock is
// refused rather than cut: the control headers come last, so a cut block
// could hold only copies the message itself carried.
func readHeaderBlock(r io.Reader) ([]byte, error) {
	br := bufio.NewReader(io.LimitReader(r, maxHeaderBlock+1))
	var block []byte
	for {
		line, err := br.ReadBytes('\n')
		block = append(block, line...)
		if len(block) > maxHeaderBlock {
			return nil, errHeaderBlockTooLarge
		}
		if err == io.EOF || err == nil && isBlankLine(line) {
			return block, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func (q *Quarantine) read(dir, id string) (HeldMessage, error) {
	f, info, err := openMessageFile(filepath.Join(q.sub(dir), id))
	if err != nil {
		return HeldMessage{}, err
	}
	defer f.Close()
	header, err := readHeaderBlock(f)
	if err != nil {
		return HeldMessage{}, err
	}
	hdr := parseControlHeaders(header)
	return HeldMessage{
		ID:        id,
		Forwarder: hdr[hdrForwarder],
		Recipient: hdr[hdrRecipient],
		Sender:    hdr[hdrSender],
		Reasons:   splitReasons(hdr[hdrReasons]),
		Subject:   heldSubject(header),
		HeldAt:    info.ModTime(),
		Size:      info.Size(),
	}, nil
}

// heldSubject returns the first Subject field of a header block, unfolded,
// as CleanSubject leaves it.
func heldSubject(header []byte) string {
	var raw strings.Builder
	found := false
	for _, line := range strings.Split(string(header), "\n") {
		line = strings.TrimRight(line, "\r")
		folded := line != "" && (line[0] == ' ' || line[0] == '\t')
		if found {
			if !folded {
				break
			}
			raw.WriteString(line)
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if ok && !folded && strings.EqualFold(strings.TrimRight(name, " \t"), "Subject") {
			raw.WriteString(value)
			found = true
		}
	}
	return CleanSubject(raw.String())
}

// CleanSubject readies a mail subject for the web UI: RFC 2047 encoded words
// decoded, control characters turned into spaces, bidi and other format
// characters (which can reverse or hide text) dropped, runs of space
// collapsed, and cut to maxSubjectLen runes. The subject is the sender's
// text. A charset the decoder does not know leaves the words as sent.
func CleanSubject(subject string) string {
	if decoded, err := new(mime.WordDecoder).DecodeHeader(subject); err == nil {
		subject = decoded
	}
	subject = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r):
			return ' '
		case unicode.Is(unicode.Bidi_Control, r), unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, subject)), " ")
	if r := []rune(subject); len(r) > maxSubjectLen {
		subject = string(r[:maxSubjectLen])
	}
	return subject
}

// Release re-injects the held copy to its original external recipient (operator
// decided it was a false positive), then removes it. The message is removed
// only after a successful re-injection, so a sendmail failure never loses mail.
func (q *Quarantine) Release(id string) error {
	_, path := q.locate(id)
	if path == "" {
		return fmt.Errorf("held message %q not found", id)
	}
	data, _, err := readMessageFile(path)
	if err != nil {
		return err
	}
	header, err := readHeaderBlock(bytes.NewReader(data))
	if err != nil {
		return err
	}
	hdr := parseControlHeaders(header)
	sender, hasSender := hdr[hdrSender]
	recipient := hdr[hdrRecipient]
	if !hasSender || sender != "" && !singleEnvelopeAddress(sender) || !singleEnvelopeAddress(recipient) {
		return errors.New("held message does not record a safe single sender and recipient")
	}
	clean := stripControlHeaders(data)
	if err := q.sendmail(sender, recipient, clean); err != nil {
		return fmt.Errorf("re-injecting held message: %w", err)
	}
	return os.Remove(path)
}

// Exim splits command-line recipients on commas, including dequoted local
// parts from its control headers. Check both the recorded and parsed forms
// so quoting cannot hide a list separator, whitespace or an option prefix.
func singleEnvelopeAddress(value string) bool {
	unsafe := func(s string) bool {
		return strings.HasPrefix(s, "-") || strings.ContainsAny(s, ",<>") ||
			strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
	}
	if value == "" || unsafe(value) {
		return false
	}
	addr, err := mail.ParseAddress(value)
	return err == nil && addr.Name == "" && !unsafe(addr.Address)
}

// Delete discards a held copy without delivering it.
func (q *Quarantine) Delete(id string) error {
	_, path := q.locate(id)
	if path == "" {
		return fmt.Errorf("held message %q not found", id)
	}
	return os.Remove(path)
}

// PruneOlderThan removes held copies older than maxAge and returns how many were
// removed.
func (q *Quarantine) PruneOlderThan(maxAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for _, dir := range []string{"new", "cur"} {
		entries, err := os.ReadDir(q.sub(dir))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return removed, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			if info.Mode().IsRegular() && info.ModTime().Before(cutoff) {
				if err := os.Remove(filepath.Join(q.sub(dir), e.Name())); err == nil {
					removed++
				}
			}
		}
	}
	return removed, nil
}

// CountsByForwarder returns how many held copies each forwarder produced.
func (q *Quarantine) CountsByForwarder() (map[string]int, error) {
	msgs, err := q.List()
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int)
	for _, m := range msgs {
		counts[m.Forwarder]++
	}
	return counts, nil
}

// pathOf returns the on-disk path of a held message id, or "" if absent.
func (q *Quarantine) pathOf(id string) string {
	_, path := q.locate(id)
	return path
}

func (q *Quarantine) locate(id string) (dir, path string) {
	id = filepath.Base(id) // defend against traversal in a caller-supplied id
	if id == "" || id == "." || id == ".." || id == string(filepath.Separator) {
		return "", ""
	}
	for _, d := range []string{"new", "cur"} {
		p := filepath.Join(q.sub(d), id)
		info, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if info.Mode().IsRegular() {
			return d, p
		}
	}
	return "", ""
}

func readMessageFile(path string) ([]byte, os.FileInfo, error) {
	f, info, err := openMessageFile(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}
	return data, info, nil
}

// openMessageFile opens a held copy for reading. The caller closes it.
func openMessageFile(path string) (*os.File, os.FileInfo, error) {
	// #nosec G304 -- path is a located Maildir entry under the CSM-owned base;
	// O_NOFOLLOW rejects symlink entries and symlink swaps before reading.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("held message %q is not a regular file", filepath.Base(path))
	}
	return f, info, nil
}

// headerValue collapses a control-header value to a single safe line (no CR/LF
// so a hostile address cannot inject extra headers).
func headerValue(v string) string {
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	return strings.TrimSpace(v)
}

func splitReasons(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// headerBlockEnd returns the index just past the first blank line (the
// header/body separator), or len(data) if there is no blank line. A leading
// blank line means the header block is empty -- the rest is body. Defining the
// boundary by the first empty line (rather than searching for "\n\n") keeps
// parsing and stripping consistent on degenerate inputs.
func headerBlockEnd(data []byte) int {
	off := 0
	for off < len(data) {
		nl := bytes.IndexByte(data[off:], '\n')
		if nl < 0 {
			return len(data) // no terminating newline: all headers, no body
		}
		if isBlankLine(data[off : off+nl+1]) {
			return off + nl + 1
		}
		off += nl + 1
	}
	return len(data)
}

// isBlankLine reports whether line, with its line ending, is the blank line
// that ends a header block.
func isBlankLine(line []byte) bool {
	return len(bytes.TrimRight(line, "\r\n")) == 0
}

// parseControlHeaders returns the X-CSM-* fields of the header block that
// starts data. A message can carry its own X-CSM-* fields; exim appends the
// real ones after every field the message brought, so the last occurrence
// of each wins. A folded continuation line is never a field.
func parseControlHeaders(data []byte) map[string]string {
	out := map[string]string{}
	header := data[:headerBlockEnd(data)]
	for _, line := range strings.Split(string(header), "\n") {
		line = strings.TrimRight(line, "\r")
		colon := strings.IndexByte(line, ':')
		if colon < 0 || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, ok := canonicalControlHeader(line[:colon])
		if !ok {
			continue
		}
		out[key] = headerValue(line[colon+1:])
	}
	return out
}

func canonicalControlHeader(name string) (string, bool) {
	name = strings.TrimSpace(name)
	switch {
	case strings.EqualFold(name, hdrForwarder):
		return hdrForwarder, true
	case strings.EqualFold(name, hdrRecipient):
		return hdrRecipient, true
	case strings.EqualFold(name, hdrSender):
		return hdrSender, true
	case strings.EqualFold(name, hdrReasons):
		return hdrReasons, true
	case hasControlHeaderPrefix(name):
		return name, true
	default:
		return "", false
	}
}

func hasControlHeaderPrefix(line string) bool {
	return len(line) >= len(hdrPrefix) && strings.EqualFold(line[:len(hdrPrefix)], hdrPrefix)
}

// stripControlHeaders removes every X-CSM-* header line, leaving the original
// message intact for re-injection. Only the header lines before the
// header/body separator are filtered; the separator and body are preserved
// byte-for-byte so the recipient sees exactly the original message.
func stripControlHeaders(data []byte) []byte {
	var kept bytes.Buffer
	rest := data
	droppingControl := false
	for len(rest) > 0 {
		nl := bytes.IndexByte(rest, '\n')
		var line []byte
		if nl < 0 {
			line, rest = rest, nil
		} else {
			line, rest = rest[:nl+1], rest[nl+1:]
		}
		trimmed := strings.TrimRight(string(line), "\r\n")
		if trimmed == "" {
			// Blank line ends the header block; keep it and the body verbatim.
			kept.Write(line)
			kept.Write(rest)
			return kept.Bytes()
		}
		if line[0] == ' ' || line[0] == '\t' {
			if droppingControl {
				continue
			}
			kept.Write(line)
			continue
		}
		droppingControl = hasControlHeaderPrefix(trimmed)
		if droppingControl {
			continue
		}
		kept.Write(line)
	}
	return kept.Bytes()
}

func runSendmail(sender, recipient string, body []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sender = headerValue(sender)
	recipient = headerValue(recipient)
	// -i: do not treat lone "." as end; -f: envelope sender ("" yields null
	// sender); -- terminates options so a hostile recipient cannot be a flag.
	cmd := exec.CommandContext(ctx, sendmailPath, "-i", "-f", sender, "--", recipient) // #nosec G204 -- recipient guarded by --, args are envelope addresses
	cmd.Stdin = bytes.NewReader(body)
	return cmd.Run()
}

const sendmailPath = "/usr/sbin/sendmail"
