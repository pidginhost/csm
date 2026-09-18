package mime

import (
	"bytes"
	"errors"
	"io"
	"strings"
)

// transferDecoder returns a reader that undoes a part's
// Content-Transfer-Encoding. Decoding is as lenient as mail clients are:
// anything a client would render as an attachment has to reach the scanners
// too, or a malformed encoding becomes a way to deliver unscanned content.
// Malformed input still decodes as far as clients decode it; the reader then
// reports an error so the part is marked incompletely scanned. Unknown
// encodings (7bit, 8bit, binary) pass through unchanged.
func transferDecoder(cte string, r io.Reader) io.Reader {
	switch cte {
	case "base64":
		return &decodeReader{src: r, dec: &base64Decoder{}}
	case "quoted-printable":
		return &decodeReader{src: r, dec: &qpDecoder{}}
	default:
		return r
	}
}

// transferReaders preserves client interpretations of malformed padding:
// consuming full quartets, ignoring misplaced padding, or stopping at valid
// padding. A long suffix can hide an otherwise readable archive, so scanning
// a continued decode cannot replace scanning the padded prefix. The source
// is a part of the already memory-bounded spool body.
func transferReaders(cte string, r io.Reader, result *ExtractionResult) ([]io.Reader, error) {
	if cte != "base64" {
		return []io.Reader{transferDecoder(cte, r)}, nil
	}
	body, err := io.ReadAll(r)
	readers := []io.Reader{transferDecoder(cte, bytes.NewReader(body))}
	var alternatives []io.Reader
	if prefix := base64PaddedPrefix(body); prefix != nil {
		alternatives = append(alternatives, transferDecoder(cte, bytes.NewReader(prefix)))
	}
	if ambiguousBase64Padding(body) {
		alternatives = append(alternatives, &decodeReader{src: bytes.NewReader(body), dec: &base64AlphabetDecoder{}})
	}
	for _, alternative := range alternatives {
		const maxTransferVariants = 16
		if result.transferVariants >= maxTransferVariants {
			markPartial(result, "transfer decoding exceeds alternate interpretation limit")
		} else {
			result.transferVariants++
			readers = append(readers, alternative)
		}
	}
	return readers, err
}

// Return a normally padded prefix only when meaningful data follows it.
func base64PaddedPrefix(body []byte) []byte {
	slot := 0
	padded := false
	for i, b := range body {
		_, alphabet := base64Value(b)
		switch {
		case b == '=':
			if slot < 2 {
				return nil
			}
			padded = true
		case !alphabet:
			continue
		case padded:
			return nil // the quartet itself has misplaced padding
		}
		slot++
		if slot == 4 {
			if padded {
				for _, tail := range body[i+1:] {
					if _, ok := base64Value(tail); ok || tail == '=' {
						return body[:i+1]
					}
				}
				return nil
			}
			slot = 0
		}
	}
	return nil
}

func ambiguousBase64Padding(body []byte) bool {
	slot, pads := 0, 0
	for _, b := range body {
		if b == '=' {
			if slot < 2 {
				return true
			}
			pads++
		} else if _, ok := base64Value(b); !ok {
			continue
		} else if pads > 0 {
			return true
		}
		slot++
		if slot == 4 {
			slot, pads = 0, 0
		}
	}
	return false
}

type base64AlphabetDecoder struct{ base64Decoder }

func (d *base64AlphabetDecoder) feed(b byte, out []byte) []byte {
	if b == '=' {
		return out
	}
	return d.base64Decoder.feed(b, out)
}

var (
	errBase64AfterPadding = errors.New("base64 data after padding")
	errBase64Truncated    = errors.New("base64 data ends with an incomplete byte")
	errBase64Padding      = errors.New("misplaced base64 padding")
)

// byteDecoder turns encoded bytes into decoded bytes one input byte at a
// time. finish flushes held state at end of input and reports malformed input
// that was nonetheless decoded.
type byteDecoder interface {
	feed(b byte, out []byte) []byte
	finish(out []byte) ([]byte, error)
}

// decodeReader drives a byteDecoder. Decoded output is drained before any
// error is returned, so a caller always sees every byte a client would.
type decodeReader struct {
	src     io.Reader
	dec     byteDecoder
	buf     [4096]byte
	pending []byte
	err     error
}

func (d *decodeReader) Read(p []byte) (int, error) {
	for len(d.pending) == 0 && d.err == nil {
		n, err := d.src.Read(d.buf[:])
		out := d.pending[:0]
		for _, b := range d.buf[:n] {
			out = d.dec.feed(b, out)
		}
		if err != nil {
			var decodeErr error
			out, decodeErr = d.dec.finish(out)
			// A truncated MIME part returns UnexpectedEOF. Its buffered
			// tail still carries bytes; preserve the source error too.
			if err == io.EOF && decodeErr != nil {
				err = decodeErr
			}
		}
		d.pending = out
		d.err = err
	}
	if len(d.pending) == 0 {
		return 0, d.err
	}
	n := copy(p, d.pending)
	d.pending = d.pending[n:]
	return n, nil
}

// base64Decoder decodes quartet by quartet and ignores every byte outside
// the alphabet, as RFC 2045 section 6.8 requires. Padding occupies a slot
// in the quartet, even when misplaced. Resetting at '=' instead would shift
// all subsequent bytes compared with clients that consume full quartets.
type base64Decoder struct {
	quad         [4]byte
	n            int
	padding      int
	badPadding   bool
	sawPad       bool
	afterPadData bool
}

func (d *base64Decoder) feed(b byte, out []byte) []byte {
	v, ok := base64Value(b)
	switch {
	case b == '=':
		if d.n < 2 {
			d.badPadding = true
		}
		d.padding++
		d.sawPad = true
	case !ok:
		return out
	case d.sawPad:
		d.afterPadData = true
	}
	d.quad[d.n] = v
	d.n++
	if d.n == 4 {
		out = d.flush(out)
		d.n = 0
		d.padding = 0
	}
	return out
}

// Clients such as Thunderbird emit at least one byte even for a quartet
// containing three or four padding characters.
func (d *base64Decoder) flush(out []byte) []byte {
	q := d.quad
	out = append(out, q[0]<<2|q[1]>>4)
	if d.padding < 2 {
		out = append(out, q[1]<<4|q[2]>>2)
	}
	if d.padding == 0 {
		out = append(out, q[2]<<6|q[3])
	}
	return out
}

func (d *base64Decoder) finish(out []byte) ([]byte, error) {
	var err error
	switch {
	case d.n >= 2:
		for d.n < 4 {
			d.quad[d.n] = 0
			d.n++
			d.padding++
		}
		out = d.flush(out) // missing final padding
	case d.n == 1:
		err = errBase64Truncated
	}
	d.n = 0
	if d.badPadding {
		err = errBase64Padding
	}
	if d.afterPadData {
		err = errBase64AfterPadding
	}
	return out, err
}

func base64Value(b byte) (byte, bool) {
	switch {
	case b >= 'A' && b <= 'Z':
		return b - 'A', true
	case b >= 'a' && b <= 'z':
		return b - 'a' + 26, true
	case b >= '0' && b <= '9':
		return b - '0' + 52, true
	case b == '+':
		return 62, true
	case b == '/':
		return 63, true
	}
	return 0, false
}

// qpDecoder decodes quoted-printable without ever failing: an escape that is
// not two hex digits is kept literally, a soft line break may end in CR, LF or
// CRLF, raw control bytes pass through, and lines have no length limit.
// Whitespace before a line break is transport padding and is dropped
// (RFC 2045 section 6.7, rule 3).
type qpDecoder struct {
	state qpState
	hex1  byte
	ws    []byte // whitespace held until the next byte shows whether it ends a line
}

type qpState int

const (
	qpText     qpState = iota
	qpEquals           // saw '='
	qpEqualsH1         // saw '=' and one hex digit
	qpEqualsWS         // saw '=' followed by whitespace: soft break if a line break follows
	qpSoftCR           // soft break ended in CR; swallow a following LF
)

func (d *qpDecoder) feed(b byte, out []byte) []byte {
	switch d.state {
	case qpEquals:
		switch {
		case isHexDigit(b):
			d.hex1 = b
			d.state = qpEqualsH1
			return out
		case b == ' ' || b == '\t':
			d.ws = append(d.ws[:0], b)
			d.state = qpEqualsWS
			return out
		case b == '\r':
			d.state = qpSoftCR
			return out
		case b == '\n':
			d.state = qpText
			return out
		}
		out = append(out, '=')
		d.state = qpText
	case qpEqualsH1:
		d.state = qpText
		if isHexDigit(b) {
			return append(out, hexValue(d.hex1)<<4|hexValue(b))
		}
		out = append(out, '=', d.hex1)
	case qpEqualsWS:
		switch b {
		case ' ', '\t':
			d.ws = append(d.ws, b)
			return out
		case '\r':
			d.ws = d.ws[:0]
			d.state = qpSoftCR
			return out
		case '\n':
			d.ws = d.ws[:0]
			d.state = qpText
			return out
		}
		out = append(out, '=')
		out = append(out, d.ws...)
		d.ws = d.ws[:0]
		d.state = qpText
	case qpSoftCR:
		d.state = qpText
		if b == '\n' {
			return out
		}
	}

	switch b {
	case '=':
		out = append(out, d.ws...)
		d.ws = d.ws[:0]
		d.state = qpEquals
	case ' ', '\t':
		d.ws = append(d.ws, b)
	case '\r', '\n':
		d.ws = d.ws[:0]
		out = append(out, b)
	default:
		out = append(out, d.ws...)
		d.ws = d.ws[:0]
		out = append(out, b)
	}
	return out
}

func (d *qpDecoder) finish(out []byte) ([]byte, error) {
	switch d.state {
	case qpEquals:
		out = append(out, '=')
	case qpEqualsH1:
		out = append(out, '=', d.hex1)
	}
	// Trailing whitespace on the last line and a trailing "= " soft break
	// carry no data.
	d.ws = d.ws[:0]
	d.state = qpText
	return out, nil
}

func isHexDigit(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'F' || b >= 'a' && b <= 'f'
}

func hexValue(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	default:
		return b - 'A' + 10
	}
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

// DecodeTransferVariants decodes data under Content-Transfer-Encoding cte the
// way attachment extraction does: leniently, and under every reading of
// ambiguous base64 a mail client could apply. Decode errors are ignored; each
// variant holds every byte that decoded.
func DecodeTransferVariants(cte string, data []byte) [][]byte {
	readers, _ := transferReaders(strings.ToLower(strings.TrimSpace(cte)), bytes.NewReader(data), &ExtractionResult{})
	variants := make([][]byte, 0, len(readers))
	for _, r := range readers {
		decoded, _ := io.ReadAll(r)
		variants = append(variants, decoded)
	}
	return variants
}
