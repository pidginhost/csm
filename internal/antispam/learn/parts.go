package learn

import (
	"bufio"
	"bytes"
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
		h, err := textproto.NewReader(bufio.NewReader(io.MultiReader(bytes.NewReader(head), strings.NewReader(eol)))).ReadMIMEHeader()
		if err != nil {
			return
		}
		parts := make([]textPart, 0, limit)
		if !collectTextParts(h, body, 1, limit, &parts) || len(parts) == 0 {
			return
		}
		fields := keptFields(head)
		for _, p := range parts {
			var b bytes.Buffer
			b.Write(fields)
			b.WriteString("MIME-Version: 1.0" + eol)
			if ct := p.header.Get("Content-Type"); ct != "" {
				b.WriteString("Content-Type: " + ct + eol)
			}
			if cte := p.header.Get("Content-Transfer-Encoding"); cte != "" {
				b.WriteString("Content-Transfer-Encoding: " + cte + eol)
			}
			b.WriteString(eol)
			b.Write(p.body)
			if !yield(b.Bytes()) {
				return
			}
		}
	}
}

// collectTextParts keeps only the largest limit inline parts, in descending
// size and wire order for ties. It reports false when h is not multipart or
// the nesting is too deep.
func collectTextParts(h textproto.MIMEHeader, body []byte, depth, limit int, out *[]textPart) bool {
	mt, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mt, "multipart/") || params["boundary"] == "" {
		return false
	}
	if attachment(h) {
		return true
	}
	r := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		p, err := r.NextRawPart()
		if err != nil {
			return true
		}
		if attachment(p.Header) {
			continue
		}
		pmt := "text/plain"
		if ct := p.Header.Get("Content-Type"); ct != "" {
			if pmt, _, err = mime.ParseMediaType(ct); err != nil {
				continue
			}
		}
		if pmt != "text/plain" && pmt != "text/html" && !strings.HasPrefix(pmt, "multipart/") {
			continue
		}
		raw, err := io.ReadAll(p)
		if err != nil {
			return true
		}
		switch {
		case strings.HasPrefix(pmt, "multipart/"):
			if depth == maxPartDepth || !collectTextParts(p.Header, raw, depth+1, limit, out) {
				return false
			}
		default:
			i := sort.Search(len(*out), func(i int) bool { return len((*out)[i].body) < len(raw) })
			if i == limit {
				continue
			}
			if len(*out) < limit {
				*out = append(*out, textPart{})
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
