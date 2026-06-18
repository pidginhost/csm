package checks

import (
	"bytes"
	"strings"
)

// wpTranslationMaxDepth bounds array nesting so a crafted file cannot drive
// unbounded recursion in the recognizer. Real translation caches nest one
// level deep (the "messages" map), so this leaves ample headroom.
const wpTranslationMaxDepth = 16

// IsWPTranslationCacheBytesComplete reports whether buf is exactly a WordPress
// PHP translation cache: the "<?php" opener, the keyword "return", a single PHP
// array literal whose elements are only string/integer scalars (optionally
// concatenated string literals, as GlotPress joins plural forms with a "\0"
// separator) or nested arrays of the same, then a ";" and nothing else.
// WordPress 6.5+ auto-generates these as pure data return maps (*.l10n.php);
// each one previously opened a sensitive-dir Warning incident.
//
// This is a content-structure recognizer, not a path or filename allowlist. A
// variable, a function call, string interpolation, a concatenation operand that
// is not a literal, a closing "?>" tag, or any statement after the array makes
// it return false, so an attacker cannot smuggle code into a file shaped like a
// translation cache. complete must be true: a truncated buffer cannot prove the
// unseen tail carries no code, so it is never suppressed.
func IsWPTranslationCacheBytesComplete(buf []byte, complete bool) bool {
	if !complete || len(buf) == 0 {
		return false
	}
	if len(buf) >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF {
		buf = buf[3:]
	}
	s := &phpLiteralScanner{buf: buf}
	s.skipSpace()
	if !s.consumeOpener() {
		return false
	}
	s.skipTrivia()
	if id, ok := s.readIdent(); !ok || id != "return" {
		return false
	}
	s.skipTrivia()
	if !s.parseTopArray() {
		return false
	}
	s.skipTrivia()
	if s.i >= len(s.buf) || s.buf[s.i] != ';' {
		return false
	}
	s.i++
	s.skipTrivia()
	return s.i == len(s.buf)
}

// phpLiteralScanner walks a byte buffer that is expected to be a constant PHP
// data literal. It never evaluates anything; it only proves the bytes contain
// no executable construct.
type phpLiteralScanner struct {
	buf []byte
	i   int
}

// skipSpace advances past whitespace only. Used before the open tag, where any
// non-whitespace would be raw output (HTML) rather than a PHP comment.
func (s *phpLiteralScanner) skipSpace() {
	for s.i < len(s.buf) && isPHPSpace(s.buf[s.i]) {
		s.i++
	}
}

// skipTrivia advances past whitespace and PHP comments. A "/*" without a
// matching "*/" consumes to EOF, leaving the scanner at the end so callers
// expecting a token fail closed.
func (s *phpLiteralScanner) skipTrivia() {
	for s.i < len(s.buf) {
		c := s.buf[s.i]
		if isPHPSpace(c) {
			s.i++
			continue
		}
		if c == '#' || (c == '/' && s.i+1 < len(s.buf) && s.buf[s.i+1] == '/') {
			s.i = skipPHPLineComment(s.buf, s.i)
			continue
		}
		if c == '/' && s.i+1 < len(s.buf) && s.buf[s.i+1] == '*' {
			end := bytes.Index(s.buf[s.i+2:], []byte("*/"))
			if end < 0 {
				s.i = len(s.buf)
				return
			}
			s.i += 2 + end + 2
			continue
		}
		return
	}
}

func (s *phpLiteralScanner) consumeOpener() bool {
	const opener = "<?php"
	if !bytes.HasPrefix(s.buf[s.i:], []byte(opener)) {
		return false
	}
	s.i += len(opener)
	// PHP requires whitespace (or EOF) after the tag; "<?phpreturn" is invalid
	// and "<?=" is the short-echo opener, which emits output.
	if s.i < len(s.buf) && !isPHPSpace(s.buf[s.i]) {
		return false
	}
	return true
}

func (s *phpLiteralScanner) readIdent() (string, bool) {
	if s.i >= len(s.buf) || !isIdentStart(s.buf[s.i]) {
		return "", false
	}
	start := s.i
	for s.i < len(s.buf) && isIdentCont(s.buf[s.i]) {
		s.i++
	}
	return strings.ToLower(string(s.buf[start:s.i])), true
}

// parseTopArray requires the value at the cursor to be an array literal. A bare
// scalar return (return 'x';) is not a translation cache.
func (s *phpLiteralScanner) parseTopArray() bool {
	if s.i >= len(s.buf) {
		return false
	}
	if s.buf[s.i] == '[' {
		return s.parseArray(0, '[', ']')
	}
	if isIdentStart(s.buf[s.i]) {
		save := s.i
		if id, _ := s.readIdent(); id == "array" {
			s.skipTrivia()
			return s.parseArray(0, '(', ')')
		}
		s.i = save
	}
	return false
}

// parseValue accepts one array element value: a nested array, or a chain of
// constant scalars joined by the "." concatenation operator.
func (s *phpLiteralScanner) parseValue(depth int) bool {
	s.skipTrivia()
	if s.i >= len(s.buf) {
		return false
	}
	if s.buf[s.i] == '[' {
		return s.parseArray(depth, '[', ']')
	}
	if isIdentStart(s.buf[s.i]) {
		save := s.i
		if id, _ := s.readIdent(); id == "array" {
			s.skipTrivia()
			return s.parseArray(depth, '(', ')')
		}
		s.i = save
	}
	return s.parseConcatChain()
}

// parseArray consumes an array literal delimited by open/close. Elements are
// "value" or "value => value"; an empty array and a trailing comma are allowed.
func (s *phpLiteralScanner) parseArray(depth int, open, close byte) bool {
	if depth >= wpTranslationMaxDepth {
		return false
	}
	if s.i >= len(s.buf) || s.buf[s.i] != open {
		return false
	}
	s.i++
	for {
		s.skipTrivia()
		if s.i >= len(s.buf) {
			return false
		}
		if s.buf[s.i] == close {
			s.i++
			return true
		}
		if !s.parseValue(depth + 1) {
			return false
		}
		s.skipTrivia()
		if s.i+1 < len(s.buf) && s.buf[s.i] == '=' && s.buf[s.i+1] == '>' {
			s.i += 2
			if !s.parseValue(depth + 1) {
				return false
			}
			s.skipTrivia()
		}
		if s.i >= len(s.buf) {
			return false
		}
		switch s.buf[s.i] {
		case ',':
			s.i++
		case close:
			s.i++
			return true
		default:
			return false
		}
	}
}

func (s *phpLiteralScanner) parseConcatChain() bool {
	if !s.parseScalar() {
		return false
	}
	for {
		s.skipTrivia()
		if s.i < len(s.buf) && s.buf[s.i] == '.' {
			s.i++
			if !s.parseScalar() {
				return false
			}
			continue
		}
		return true
	}
}

func (s *phpLiteralScanner) parseScalar() bool {
	s.skipTrivia()
	if s.i >= len(s.buf) {
		return false
	}
	c := s.buf[s.i]
	switch {
	case c == '\'':
		return s.parseSingleQuoted()
	case c == '"':
		return s.parseDoubleQuoted()
	case c == '-' || (c >= '0' && c <= '9'):
		return s.parseInt()
	case isIdentStart(c):
		id, ok := s.readIdent()
		return ok && (id == "true" || id == "false" || id == "null")
	default:
		return false
	}
}

// parseSingleQuoted consumes a PHP single-quoted string. Inside one, only "\\"
// and "\'" are escapes and "$" never interpolates, so the contents are inert.
func (s *phpLiteralScanner) parseSingleQuoted() bool {
	s.i++ // opening quote
	for s.i < len(s.buf) {
		switch s.buf[s.i] {
		case '\\':
			s.i += 2
		case '\'':
			s.i++
			return true
		default:
			s.i++
		}
	}
	return false // unterminated
}

// parseDoubleQuoted consumes a PHP double-quoted string. A backslash escapes
// the next byte (so "\0", "\n", "\$" are literal). An unescaped "$" introduces
// variable interpolation, which is an execution vector, so it is rejected.
func (s *phpLiteralScanner) parseDoubleQuoted() bool {
	s.i++ // opening quote
	for s.i < len(s.buf) {
		switch s.buf[s.i] {
		case '\\':
			s.i += 2
		case '"':
			s.i++
			return true
		case '$':
			return false
		default:
			s.i++
		}
	}
	return false // unterminated
}

func (s *phpLiteralScanner) parseInt() bool {
	if s.buf[s.i] == '-' {
		s.i++
	}
	start := s.i
	for s.i < len(s.buf) && s.buf[s.i] >= '0' && s.buf[s.i] <= '9' {
		s.i++
	}
	return s.i > start
}

// isWPTranslationCache is the path-based entry point for the polled scan. It
// reads up to the same window as IsBenignPHPStub and requires the whole file to
// fit, since the recognizer must see the entire body to prove it is inert.
func isWPTranslationCache(path string) bool {
	f, err := osFS.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, benignPHPStubMaxScan)
	n, _ := f.Read(buf)
	if n == 0 {
		return false
	}
	info, err := f.Stat()
	complete := err == nil && info.Size() <= int64(n)
	return IsWPTranslationCacheBytesComplete(buf[:n], complete)
}
