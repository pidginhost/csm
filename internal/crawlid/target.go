package crawlid

import (
	"bytes"
	"errors"
	"sort"
	"strings"
)

var (
	ErrEmptyTarget     = errors.New("crawlid: empty target")
	ErrUnsupportedForm = errors.New("crawlid: target is neither origin-form nor http(s) absolute-form")
	ErrTargetTooLong   = errors.New("crawlid: target exceeds bound")
)

// Target is the canonical identity of one request target.
type Target struct {
	Segment  []byte   // first path segment, percent-decoded once, case kept
	HasQuery bool     // a non-empty raw query follows the first '?'
	Names    [][]byte // normalized parameter names, sorted, deduplicated
	Ext      string   // lower-case extension of the raw final path element
}

// ParseTarget canonicalizes a raw target as it appears in the request line or
// PHP's REQUEST_URI. A target longer than maxLen is an explicit overflow:
// callers must not build an identity from a prefix. The bound counts every
// raw byte, including an absolute-form scheme and authority.
func ParseTarget(raw string, maxLen int) (Target, error) {
	switch {
	case raw == "":
		return Target{}, ErrEmptyTarget
	case len(raw) > maxLen:
		return Target{}, ErrTargetTooLong
	}
	p, q, ok := SplitTarget(raw)
	if !ok {
		return Target{}, ErrUnsupportedForm
	}
	seg := p[1:]
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg = seg[:i]
	}
	t := Target{Segment: percentDecode(seg, false), Ext: PathExtension(p)}
	if q != "" {
		t.HasQuery = true
		t.Names = queryNames(q)
	}
	return t, nil
}

// PathExtension mirrors path.Ext on the raw, undecoded path: the text after the last
// '.' of the final '/'-separated element, ASCII lower-cased.
func PathExtension(p string) string {
	elem := p[strings.LastIndexByte(p, '/')+1:]
	dot := strings.LastIndexByte(elem, '.')
	if dot < 0 {
		return ""
	}
	return string(asciiLower([]byte(elem[dot+1:])))
}

// queryNames splits fields at raw '&' and names at the first raw '=' before
// any decoding. Empty fields are ignored; an explicitly empty name is kept.
// Values are never decoded or retained.
func queryNames(q string) [][]byte {
	seen := make(map[string]struct{})
	var out [][]byte
	for q != "" {
		field, rest, _ := strings.Cut(q, "&")
		q = rest
		if field == "" {
			continue
		}
		name, _, _ := strings.Cut(field, "=")
		n := normalizeBrackets(asciiLower(percentDecode(name, true)))
		if _, dup := seen[string(n)]; dup {
			continue
		}
		seen[string(n)] = struct{}{}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

// percentDecode decodes each valid %XX escape once. Invalid or short escapes
// stay literal. With plusSpace, '+' becomes a space (query names only).
func percentDecode(s string, plusSpace bool) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			out = append(out, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
		case c == '+' && plusSpace:
			out = append(out, ' ')
		default:
			out = append(out, c)
		}
	}
	return out
}

// normalizeBrackets rewrites every empty or all-digit component of a complete
// trailing bracket chain to "[]": a[0][x] -> a[][x]. A chain needs a non-empty
// base; named components and incomplete chains stay literal.
func normalizeBrackets(n []byte) []byte {
	first := bytes.IndexByte(n, '[')
	if first <= 0 || bytes.IndexByte(n[:first], ']') >= 0 {
		return n
	}
	out := append([]byte{}, n[:first]...)
	for pos := first; pos < len(n); {
		if n[pos] != '[' {
			return n
		}
		closeAt := bytes.IndexByte(n[pos+1:], ']')
		if closeAt < 0 {
			return n
		}
		end := pos + 1 + closeAt
		inner := n[pos+1 : end]
		if bytes.IndexByte(inner, '[') >= 0 {
			return n
		}
		out = append(out, '[')
		if len(inner) != 0 && !allDigits(inner) {
			out = append(out, inner...)
		}
		out = append(out, ']')
		pos = end + 1
	}
	return out
}

func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

func allDigits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	default:
		return c - 'a' + 10
	}
}

// SplitTarget returns the raw path and query of an origin-form target or of
// an http or https absolute-form target (scheme compared in ASCII case only).
// Servers must accept absolute-form and hand it to PHP unchanged, so without
// this a client could choose it to leave its identity. The authority is
// dropped: the site comes from verified inventory, never from the request.
// A target without a path, including one that starts with '?', is served at
// the root path. Any other form, such as asterisk, authority-form, another
// scheme or a rootless path, is unsupported.
func SplitTarget(raw string) (path, query string, ok bool) {
	rest := raw
	if !strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "?") {
		scheme, after, found := strings.Cut(raw, ":")
		if !found || !isHTTPScheme(scheme) {
			return "", "", false
		}
		rest = after
		if authority, hasAuthority := strings.CutPrefix(rest, "//"); hasAuthority {
			rest = ""
			if end := strings.IndexAny(authority, "/?"); end >= 0 {
				rest = authority[end:]
			}
		}
		if rest != "" && rest[0] != '/' && rest[0] != '?' {
			return "", "", false
		}
	}
	path, query, _ = strings.Cut(rest, "?")
	if path == "" {
		path = "/"
	}
	return path, query, true
}

func isHTTPScheme(s string) bool {
	if len(s) != len("http") && len(s) != len("https") {
		return false
	}
	lower := string(asciiLower([]byte(s)))
	return lower == "http" || lower == "https"
}
