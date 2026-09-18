package mime

import (
	"encoding/base64"
	"io"
	"mime/quotedprintable"
)

// transferDecoder returns a reader that undoes a part's
// Content-Transfer-Encoding. Decoding is as lenient as mail clients are:
// anything a client would render as an attachment has to reach the scanners
// too, or a malformed encoding becomes a way to deliver unscanned content.
// Unknown encodings (7bit, 8bit, binary) pass through unchanged.
func transferDecoder(cte string, r io.Reader) io.Reader {
	switch cte {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, &base64AlphabetFilter{r: r})
	case "quoted-printable":
		return quotedprintable.NewReader(&qpControlEscaper{r: r})
	default:
		return r
	}
}

// base64AlphabetFilter drops every byte outside the base64 alphabet and
// supplies missing final padding. RFC 2045 section 6.8 says such bytes are
// ignored; the standard decoder rejects anything but CR and LF. Data after
// padding is passed on and still fails to decode, because clients do not
// agree on what it means.
type base64AlphabetFilter struct {
	r      io.Reader
	chars  int // alphabet characters seen, excluding '='
	padded bool
	tail   []byte
	eof    bool
}

func (f *base64AlphabetFilter) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if len(f.tail) > 0 {
			n := copy(p, f.tail)
			f.tail = f.tail[n:]
			return n, nil
		}
		if f.eof {
			return 0, io.EOF
		}
		n, err := f.r.Read(p)
		kept := 0
		for _, b := range p[:n] {
			switch {
			case b == '=':
				f.padded = true
			case isBase64Alphabet(b):
				f.chars++
			default:
				continue
			}
			p[kept] = b
			kept++
		}
		if err == io.EOF {
			f.eof = true
			if !f.padded {
				switch f.chars % 4 {
				case 2:
					f.tail = []byte("==")
				case 3:
					f.tail = []byte("=")
				}
			}
			err = nil
		}
		if kept > 0 || err != nil {
			return kept, err
		}
	}
}

func isBase64Alphabet(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '/'
}

// qpControlEscaper rewrites raw control bytes as =XX escapes, which decode
// back to the same byte. The standard reader aborts on an unescaped control
// byte; mail readers pass it through.
type qpControlEscaper struct {
	r       io.Reader
	pending []byte
	err     error
	buf     [512]byte
}

func (e *qpControlEscaper) Read(p []byte) (int, error) {
	for len(e.pending) == 0 && e.err == nil {
		n, err := e.r.Read(e.buf[:])
		for _, b := range e.buf[:n] {
			if b < ' ' && b != '\t' && b != '\r' && b != '\n' || b == 0x7f {
				const hex = "0123456789ABCDEF"
				e.pending = append(e.pending, '=', hex[b>>4], hex[b&0x0f])
				continue
			}
			e.pending = append(e.pending, b)
		}
		e.err = err
	}
	if len(e.pending) == 0 {
		return 0, e.err
	}
	n := copy(p, e.pending)
	e.pending = e.pending[n:]
	return n, nil
}

// readErrRecorder remembers the error its source returned, so a failed copy
// can be attributed to decoding rather than to writing the staged file.
type readErrRecorder struct {
	r   io.Reader
	err error
}

func (rr *readErrRecorder) Read(p []byte) (int, error) {
	n, err := rr.r.Read(p)
	if err != nil && err != io.EOF {
		rr.err = err
	}
	return n, err
}
