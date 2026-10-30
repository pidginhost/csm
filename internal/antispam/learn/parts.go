package learn

import (
	"bufio"
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"slices"
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

// textPartMessages returns one single-part message per inline text/plain or
// text/html part of a multipart msg, the largest part first. Each keeps the
// original header fields except Content-* and MIME-Version, then the part's
// own content type and transfer encoding, then its undecoded body. A message
// that is not multipart, has no header break, carries an unreadable header or
// nests deeper than maxPartDepth yields none. Parts after a broken boundary
// are dropped.
func textPartMessages(msg []byte) [][]byte {
	head, body, eol, ok := splitHeader(msg)
	if !ok {
		return nil
	}
	h, err := textproto.NewReader(bufio.NewReader(io.MultiReader(bytes.NewReader(head), strings.NewReader(eol)))).ReadMIMEHeader()
	if err != nil {
		return nil
	}
	var parts []textPart
	if !collectTextParts(h, body, 1, &parts) {
		return nil
	}
	slices.SortStableFunc(parts, func(a, b textPart) int { return len(b.body) - len(a.body) })
	fields := keptFields(head)
	out := make([][]byte, 0, len(parts))
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
		out = append(out, b.Bytes())
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// collectTextParts appends the inline text parts of the multipart entity
// with header h and body. It reports false when h is not multipart or the
// nesting is too deep.
func collectTextParts(h textproto.MIMEHeader, body []byte, depth int, out *[]textPart) bool {
	mt, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mt, "multipart/") || params["boundary"] == "" {
		return false
	}
	r := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		p, err := r.NextRawPart()
		if err != nil {
			return true
		}
		raw, err := io.ReadAll(p)
		if err != nil {
			return true
		}
		pmt := "text/plain"
		if ct := p.Header.Get("Content-Type"); ct != "" {
			if pmt, _, err = mime.ParseMediaType(ct); err != nil {
				continue
			}
		}
		switch {
		case strings.HasPrefix(pmt, "multipart/"):
			if depth == maxPartDepth || !collectTextParts(p.Header, raw, depth+1, out) {
				return false
			}
		case (pmt == "text/plain" || pmt == "text/html") && !attachment(p.Header):
			*out = append(*out, textPart{header: p.Header, body: raw})
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
