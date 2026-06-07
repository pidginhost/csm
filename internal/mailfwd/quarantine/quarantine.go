// Package quarantine is the CSM-owned Maildir that holds external forward
// copies the forward-guard decided to withhold. The exim transport (Phase 2
// Slice C) appends held copies here with X-CSM-* control headers; CSM lists
// them, releases (re-injects to the original external recipient) or deletes,
// and prunes by age. CSM is never in the live delivery path -- exim writes the
// file, CSM only acts on it afterwards.
package quarantine

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
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
// these files; Hold produces the identical format for CSM-side paths and tests.
func (q *Quarantine) Hold(m HeldMessage, body []byte) (string, error) {
	for _, d := range []string{"tmp", "new", "cur"} {
		if err := os.MkdirAll(q.sub(d), 0700); err != nil {
			return "", fmt.Errorf("creating maildir %s: %w", d, err)
		}
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s: %s\r\n", hdrForwarder, headerValue(m.Forwarder))
	fmt.Fprintf(&buf, "%s: %s\r\n", hdrRecipient, headerValue(m.Recipient))
	fmt.Fprintf(&buf, "%s: %s\r\n", hdrSender, headerValue(m.Sender))
	fmt.Fprintf(&buf, "%s: %s\r\n", hdrReasons, headerValue(strings.Join(m.Reasons, ",")))
	buf.Write(body)

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

func (q *Quarantine) read(dir, id string) (HeldMessage, error) {
	path := filepath.Join(q.sub(dir), id)
	data, err := os.ReadFile(path) // #nosec G304 -- id is a Maildir entry name under the CSM-owned base
	if err != nil {
		return HeldMessage{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return HeldMessage{}, err
	}
	hdr := parseControlHeaders(data)
	return HeldMessage{
		ID:        id,
		Forwarder: hdr[hdrForwarder],
		Recipient: hdr[hdrRecipient],
		Sender:    hdr[hdrSender],
		Reasons:   splitReasons(hdr[hdrReasons]),
		HeldAt:    info.ModTime(),
		Size:      info.Size(),
	}, nil
}

// Release re-injects the held copy to its original external recipient (operator
// decided it was a false positive), then removes it. The message is removed
// only after a successful re-injection, so a sendmail failure never loses mail.
func (q *Quarantine) Release(id string) error {
	_, path := q.locate(id)
	if path == "" {
		return fmt.Errorf("held message %q not found", id)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- id located under the CSM-owned base
	if err != nil {
		return err
	}
	hdr := parseControlHeaders(data)
	clean := stripControlHeaders(data)
	if err := q.sendmail(hdr[hdrSender], hdr[hdrRecipient], clean); err != nil {
		return fmt.Errorf("re-injecting held message: %w", err)
	}
	return os.Remove(path)
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
			if info.ModTime().Before(cutoff) {
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
	for _, d := range []string{"new", "cur"} {
		p := filepath.Join(q.sub(d), id)
		if _, err := os.Stat(p); err == nil {
			return d, p
		}
	}
	return "", ""
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
		line := data[off : off+nl+1]
		if strings.TrimRight(string(line), "\r\n") == "" {
			return off + nl + 1
		}
		off += nl + 1
	}
	return len(data)
}

func parseControlHeaders(data []byte) map[string]string {
	out := map[string]string{}
	header := data[:headerBlockEnd(data)]
	for _, line := range strings.Split(string(header), "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, hdrPrefix) {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])
		out[key] = val
	}
	return out
}

// stripControlHeaders removes every X-CSM-* header line, leaving the original
// message intact for re-injection. Only the header lines before the
// header/body separator are filtered; the separator and body are preserved
// byte-for-byte so the recipient sees exactly the original message.
func stripControlHeaders(data []byte) []byte {
	var kept bytes.Buffer
	rest := data
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
		if strings.HasPrefix(trimmed, hdrPrefix) {
			continue
		}
		kept.Write(line)
	}
	return kept.Bytes()
}

func runSendmail(sender, recipient string, body []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// -i: do not treat lone "." as end; -f: envelope sender ("" yields null
	// sender); -- terminates options so a hostile recipient cannot be a flag.
	cmd := exec.CommandContext(ctx, sendmailPath, "-i", "-f", sender, "--", recipient) // #nosec G204 -- recipient guarded by --, args are envelope addresses
	cmd.Stdin = bytes.NewReader(body)
	return cmd.Run()
}

const sendmailPath = "/usr/sbin/sendmail"
