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

// regexGate is a conjunction of literal sets: every match of its regex
// contains at least one literal of each set, once the content is folded by
// foldForGate. The rule regexes are case-insensitive, and Go's engine cannot
// use a literal to skip ahead under case folding, so each one walks the whole
// file; a regex with a set none of whose literals is present cannot match and
// need not run. A nil gate admits every input.
type regexGate []literalSet

// literalSet lists lowercase ASCII literals of which a match contains at
// least one.
type literalSet []string

// gateFor derives the gate for a regex source written in the syntax
// regexp.Compile accepts. Sets whose shortest literal is under
// minGateLiteral bytes are left out: dropping a set only weakens the gate.
func gateFor(src string) regexGate {
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return nil
	}
	var gate regexGate
	listed := map[string]bool{}
	for _, set := range requiredSets(re) {
		if shortest(set) < minGateLiteral {
			continue
		}
		sort.Strings(set)
		set = compactStrings(set)
		key := strings.Join(set, "\x00")
		if listed[key] {
			continue
		}
		listed[key] = true
		gate = append(gate, literalSet(set))
	}
	sort.Slice(gate, func(i, j int) bool {
		return strings.Join(gate[i], "\x00") < strings.Join(gate[j], "\x00")
	})
	return gate
}

// requiredSets returns literal sets that every match of re satisfies, each
// by containing at least one of the set's literals; nil when none is known.
// A literal is the lowercased longest ASCII run of a literal node: a match
// of the node contains that run, rune for rune up to case folding.
// Non-ASCII runes end a run because their fold partners are not all
// representable in the folded content.
func requiredSets(re *syntax.Regexp) [][]string {
	switch re.Op {
	case syntax.OpLiteral:
		if lit := longestASCIIRun(re.Rune); lit != "" {
			return [][]string{{lit}}
		}
		return nil
	case syntax.OpCapture, syntax.OpPlus:
		return requiredSets(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredSets(re.Sub[0])
		}
		return nil
	case syntax.OpConcat:
		// Every part of a concatenation is present in a match, so every
		// part's sets hold.
		var all [][]string
		for _, sub := range re.Sub {
			all = append(all, requiredSets(sub)...)
		}
		return all
	case syntax.OpAlternate:
		// A match takes one branch, so the branches' sets cannot be
		// required together. Each branch contributes its strongest set to
		// one union, and a branch without any voids it.
		var union []string
		for _, sub := range re.Sub {
			sets := requiredSets(sub)
			if len(sets) == 0 {
				return nil
			}
			best := sets[0]
			for _, set := range sets[1:] {
				if shortest(set) > shortest(best) {
					best = set
				}
			}
			union = append(union, best...)
		}
		return [][]string{union}
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

// admits reports whether folded content holds a literal of every set.
// seen memoizes literal presence for the scan in progress: many regexes
// share literals such as "eval" or "base64_decode".
func (g regexGate) admits(folded string, seen map[string]bool) bool {
	for _, set := range g {
		if !set.present(folded, seen) {
			return false
		}
	}
	return true
}

func (set literalSet) present(folded string, seen map[string]bool) bool {
	for _, lit := range set {
		found, known := seen[lit]
		if !known {
			found = strings.Contains(folded, lit)
			seen[lit] = found
		}
		if found {
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
