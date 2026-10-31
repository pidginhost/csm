package learn

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"iter"
	"mime"
	"mime/multipart"
	"net/textproto"
	"sort"
	"strings"
)

// maxPartDepth bounds multipart nesting. Every level rescans the bytes it
// encloses, so a tenant-built message cannot make splitting quadratic; real
// mail nests three or four levels.
const maxPartDepth = 8

type textPart struct {
	header textproto.MIMEHeader
	body   []byte
}

// textPartMessages yields up to limit single-part messages from inline
// text/plain or text/html parts, the largest first. Each keeps the
// original header fields except Content-* and MIME-Version, then the part's
// own content type and transfer encoding, then its undecoded body. A message
// that is not multipart, has no header break, carries an unreadable header or
// nests deeper than maxPartDepth yields none. Parts after a broken boundary
// are dropped. The caller supplies its inspection budget as limit. Shared
// headers are copied only when a message is requested, so many small parts
// cannot multiply a large header into an unbounded allocation.
func textPartMessages(msg []byte, limit int) iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		if limit <= 0 {
			return
		}
		head, body, eol, ok := splitHeader(msg)
		if !ok {
			return
		}
		h, err := readHeader(head, eol)
		if err != nil {
			return
		}
		parts := make([]textPart, 0, limit)
		var dropped bool
		if !collectTextParts(h, body, 1, limit, &parts, &dropped) || len(parts) == 0 {
			return
		}
		fields := keptFields(head)
		for _, p := range parts {
			var b bytes.Buffer
			b.Write(fields)
			b.WriteString("MIME-Version: 1.0" + eol)
			writePartHeader(&b, p, eol)
			b.WriteString(eol)
			b.Write(p.body)
			if !yield(b.Bytes()) {
				return
			}
		}
	}
}

// textOnlyMessage returns msg with only its inline text/plain and text/html
// parts: the form the learner inspects, publishes and stores. An attachment
// that rspamd hashes on its own, such as a PDF with scripts, then can neither
// break an inspection nor publish a digest the ledger does not track. A
// message with nothing to drop, or one this parser cannot read, comes back
// unchanged; one without inline text yields nil.
func textOnlyMessage(msg []byte) []byte {
	head, body, eol, ok := splitHeader(msg)
	if !ok {
		return msg
	}
	h, err := readHeader(head, eol)
	if err != nil {
		return msg
	}
	ct := h.Get("Content-Type")
	if ct == "" {
		return msg
	}
	mt, _, err := mime.ParseMediaType(ct)
	switch {
	case err != nil || strings.HasPrefix(mt, "text/"):
		return msg
	case !strings.HasPrefix(mt, "multipart/"):
		return nil
	}
	var parts []textPart
	var dropped bool
	switch {
	case !collectTextParts(h, body, 1, MaxExplicitDigests, &parts, &dropped):
		return msg
	case len(parts) == 0:
		return nil
	case !dropped:
		return msg
	}
	var b bytes.Buffer
	b.Write(keptFields(head))
	b.WriteString("MIME-Version: 1.0" + eol)
	if len(parts) == 1 {
		writePartHeader(&b, parts[0], eol)
		b.WriteString(eol)
		b.Write(parts[0].body)
		return b.Bytes()
	}
	boundary := textBoundary(msg, parts)
	b.WriteString("Content-Type: multipart/mixed; boundary=\"" + boundary + "\"" + eol + eol)
	for _, p := range parts {
		b.WriteString("--" + boundary + eol)
		writePartHeader(&b, p, eol)
		b.WriteString(eol)
		b.Write(p.body)
		b.WriteString(eol)
	}
	b.WriteString("--" + boundary + "--" + eol)
	return b.Bytes()
}

// textBoundary derives the rebuilt message's boundary from its source, so a
// retried request stores the same bytes, and avoids any part's content.
func textBoundary(msg []byte, parts []textPart) string {
	sum := sha256.Sum256(msg)
	for n := 0; ; n++ {
		boundary := fmt.Sprintf("csm-text-%x-%d", sum[:12], n)
		clash := false
		for _, p := range parts {
			if bytes.Contains(p.body, []byte(boundary)) {
				clash = true
				break
			}
		}
		if !clash {
			return boundary
		}
	}
}

func writePartHeader(b *bytes.Buffer, p textPart, eol string) {
	if ct := p.header.Get("Content-Type"); ct != "" {
		b.WriteString("Content-Type: " + ct + eol)
	}
	if cte := p.header.Get("Content-Transfer-Encoding"); cte != "" {
		b.WriteString("Content-Transfer-Encoding: " + cte + eol)
	}
}

func readHeader(head []byte, eol string) (textproto.MIMEHeader, error) {
	return textproto.NewReader(bufio.NewReader(io.MultiReader(bytes.NewReader(head), strings.NewReader(eol)))).ReadMIMEHeader()
}

// collectTextParts keeps only the largest limit inline parts, in descending
// size and wire order for ties, and sets dropped when it leaves any part out.
// It reports false when h is not multipart or the nesting is too deep.
func collectTextParts(h textproto.MIMEHeader, body []byte, depth, limit int, out *[]textPart, dropped *bool) bool {
	mt, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mt, "multipart/") || params["boundary"] == "" {
		return false
	}
	if attachment(h) {
		*dropped = true
		return true
	}
	r := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		p, err := r.NextRawPart()
		if err != nil {
			*dropped = *dropped || err != io.EOF
			return true
		}
		if attachment(p.Header) {
			*dropped = true
			continue
		}
		pmt := "text/plain"
		if ct := p.Header.Get("Content-Type"); ct != "" {
			if pmt, _, err = mime.ParseMediaType(ct); err != nil {
				*dropped = true
				continue
			}
		}
		if pmt != "text/plain" && pmt != "text/html" && !strings.HasPrefix(pmt, "multipart/") {
			*dropped = true
			continue
		}
		raw, err := io.ReadAll(p)
		if err != nil {
			*dropped = true
			return true
		}
		switch {
		case strings.HasPrefix(pmt, "multipart/"):
			if depth == maxPartDepth || !collectTextParts(p.Header, raw, depth+1, limit, out, dropped) {
				return false
			}
		default:
			i := sort.Search(len(*out), func(i int) bool { return len((*out)[i].body) < len(raw) })
			if i == limit {
				*dropped = true
				continue
			}
			if len(*out) < limit {
				*out = append(*out, textPart{})
			} else {
				*dropped = true
			}
			copy((*out)[i+1:], (*out)[i:])
			(*out)[i] = textPart{header: p.Header, body: raw}
		}
	}
}

func attachment(h textproto.MIMEHeader) bool {
	d, _, err := mime.ParseMediaType(h.Get("Content-Disposition"))
	return err == nil && d == "attachment"
}

// splitHeader returns the header block with its last line break, the body,
// and the line break that ends the header.
func splitHeader(msg []byte) (head, body []byte, eol string, ok bool) {
	lf := bytes.Index(msg, []byte("\n\n"))
	crlf := bytes.Index(msg, []byte("\r\n\r\n"))
	switch {
	case crlf >= 0 && (lf < 0 || crlf < lf):
		return msg[:crlf+2], msg[crlf+4:], "\r\n", true
	case lf >= 0:
		return msg[:lf+1], msg[lf+2:], "\n", true
	}
	return nil, nil, "", false
}

// keptFields returns head's raw fields, folded lines included, without
// Content-* and MIME-Version.
func keptFields(head []byte) []byte {
	var out []byte
	keep := false
	for line := range bytes.Lines(head) {
		if line[0] != ' ' && line[0] != '\t' {
			name, _, _ := bytes.Cut(line, []byte(":"))
			n := strings.ToLower(strings.TrimSpace(string(name)))
			keep = !strings.HasPrefix(n, "content-") && n != "mime-version"
		}
		if keep {
			out = append(out, line...)
		}
	}
	return out
}
