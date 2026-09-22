package signatures

import (
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// minGateLiteral is the shortest literal worth testing before a regex. A
// one-byte literal occurs in nearly every file, so testing for it costs a pass
// over the content and filters nothing.
const minGateLiteral = 2

// compiledRegex is a rule regex paired with the literals that gate it.
// Identical sources across rules share one value, so a scan evaluates each
// distinct regex once.
type compiledRegex struct {
	*regexp.Regexp
	gate regexGate
}

// regexGate lists lowercase ASCII literals of which every match of its regex
// contains at least one, once the content is folded by foldForGate. The rule
// regexes are case-insensitive, and Go's engine cannot use a literal to skip
// ahead under case folding, so each one walks the whole file; a regex whose
// literals are all absent cannot match and need not run. A nil gate admits
// every input.
type regexGate []string

// gateFor derives the gate for a regex source written in the syntax
// regexp.Compile accepts. It returns nil when no literal of at least
// minGateLiteral bytes is required by every match.
func gateFor(src string) regexGate {
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return nil
	}
	gate := requiredLiterals(re)
	for _, lit := range gate {
		if len(lit) < minGateLiteral {
			return nil
		}
	}
	sort.Strings(gate)
	return regexGate(compactStrings(gate))
}

// requiredLiterals returns literals of which every match of re contains at
// least one, or nil when the structure admits a match without any. Each
// literal is a lowercased maximal ASCII run of a literal node: a match of the
// node contains that run, rune for rune up to case folding. Non-ASCII runes
// end a run because their fold partners are not all representable in the
// folded content.
func requiredLiterals(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		if lit := longestASCIIRun(re.Rune); lit != "" {
			return []string{lit}
		}
		return nil
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiterals(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredLiterals(re.Sub[0])
		}
		return nil
	case syntax.OpConcat:
		// Every part of a concatenation is present in a match, so any one
		// part's literals gate it; take the part whose shortest literal is
		// longest, as it is the least likely to occur by chance.
		var best []string
		for _, sub := range re.Sub {
			if lits := requiredLiterals(sub); lits != nil && shortest(lits) > shortest(best) {
				best = lits
			}
		}
		return best
	case syntax.OpAlternate:
		// A match takes one branch, so the gate is the union of the
		// branches' literals, and a single branch without any voids it.
		var all []string
		for _, sub := range re.Sub {
			lits := requiredLiterals(sub)
			if lits == nil {
				return nil
			}
			all = append(all, lits...)
		}
		return all
	}
	return nil
}

func longestASCIIRun(runes []rune) string {
	best, start := "", 0
	for i := 0; i <= len(runes); i++ {
		if i < len(runes) && runes[i] < utf8.RuneSelf {
			continue
		}
		if i-start > len(best) {
			best = strings.ToLower(string(runes[start:i]))
		}
		start = i + 1
	}
	return best
}

func shortest(lits []string) int {
	if len(lits) == 0 {
		return 0
	}
	n := len(lits[0])
	for _, lit := range lits[1:] {
		n = min(n, len(lit))
	}
	return n
}

func compactStrings(sorted []string) []string {
	out := sorted[:0]
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// admits reports whether folded content holds one of the gate's literals.
// seen memoizes literal presence for the scan in progress: many regexes
// share literals such as "eval" or "base64_decode".
func (g regexGate) admits(folded string, seen map[string]bool) bool {
	if len(g) == 0 {
		return true
	}
	for _, lit := range g {
		present, known := seen[lit]
		if !known {
			present = strings.Contains(folded, lit)
			seen[lit] = present
		}
		if present {
			return true
		}
	}
	return false
}

// asciiFoldOf maps each non-ASCII rune that Unicode case folding pairs with an
// ASCII letter to that letter in lower case: a case-insensitive "s" also
// matches the long s, and "k" the Kelvin sign.
var asciiFoldOf = func() map[rune]byte {
	m := map[rune]byte{}
	for c := 'a'; c <= 'z'; c++ {
		for r := unicode.SimpleFold(c); r != c; r = unicode.SimpleFold(r) {
			if r >= utf8.RuneSelf {
				m[r] = byte(c)
			}
		}
	}
	return m
}()

// foldForGate lowercases ASCII letters and replaces each non-ASCII fold
// partner of an ASCII letter with that letter. Content is decoded exactly as
// the regex engine decodes it, an invalid byte standing alone, so a literal a
// regex matches is never split or hidden by the fold.
func foldForGate(content []byte) string {
	var b strings.Builder
	b.Grow(len(content))
	for i := 0; i < len(content); {
		c := content[i]
		if c < utf8.RuneSelf {
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			b.WriteByte(c)
			i++
			continue
		}
		r, width := utf8.DecodeRune(content[i:])
		if ascii, ok := asciiFoldOf[r]; ok {
			b.WriteByte(ascii)
		} else {
			b.Write(content[i : i+width])
		}
		i += width
	}
	return b.String()
}

// regexEval evaluates rule regexes for one scan. Each distinct regex runs at
// most once, and only when its gate admits the content. The content is folded
// on first use, so a scan that reaches no gated regex never pays for it.
type regexEval struct {
	content []byte
	folded  string
	didFold bool
	seen    map[string]bool
	results map[*compiledRegex]bool
}

func newRegexEval(content []byte) *regexEval {
	return &regexEval{
		content: content,
		seen:    make(map[string]bool),
		results: make(map[*compiledRegex]bool),
	}
}

func (e *regexEval) match(cr *compiledRegex) bool {
	if matched, done := e.results[cr]; done {
		return matched
	}
	if len(cr.gate) > 0 && !e.didFold {
		e.folded, e.didFold = foldForGate(e.content), true
	}
	matched := cr.gate.admits(e.folded, e.seen) && cr.Match(e.content)
	e.results[cr] = matched
	return matched
}
