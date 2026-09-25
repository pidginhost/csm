package main

import (
	"net"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Failure links let a mismatching shared prefix resume at its suffix in
// one scan, instead of restarting a long lookup at every text boundary.
// The index is private to replacement; verification uses the learned sets.
type nameIndex struct {
	root     nameNode
	maxDepth int
	dirty    bool
}

type nameNode struct {
	next         map[rune]*nameNode
	fail, output *nameNode
	depth        int
	terminal     bool
}

func (a *Anonymizer) learnIrregular(lower string) {
	if tokenVisible(lower) || !strings.ContainsFunc(lower, func(r rune) bool {
		return unicode.IsLetter(r) || unicode.IsDigit(r)
	}) {
		// Punctuation alone is ambiguous. Keep it in the learned sets for
		// the independent refusal check, but never rewrite separators globally.
		return
	}
	a.irregular.add(lower)
}

func (index *nameIndex) add(name string) {
	node := &index.root
	for _, r := range name {
		if node.next == nil {
			node.next = make(map[rune]*nameNode)
		}
		if node.next[r] == nil {
			node.next[r] = &nameNode{depth: node.depth + 1}
		}
		node = node.next[r]
	}
	if !node.terminal {
		node.terminal = true
		index.maxDepth = max(index.maxDepth, node.depth)
		index.dirty = true
	}
}

// Learning is batched before transformation. Rebuild lazily only when a
// genuinely new name arrives, including a new suffix of an existing name.
func (index *nameIndex) prepare() {
	if !index.dirty {
		return
	}
	root := &index.root
	root.fail = root
	queue := make([]*nameNode, 0, len(root.next))
	for _, node := range root.next {
		node.fail, node.output = root, nil
		queue = append(queue, node)
	}
	for i := 0; i < len(queue); i++ {
		parent := queue[i]
		for r, node := range parent.next {
			fallback := parent.fail
			for fallback != root && fallback.next[r] == nil {
				fallback = fallback.fail
			}
			node.fail = root
			if next := fallback.next[r]; next != nil {
				node.fail = next
			}
			node.output = node.fail
			if !node.output.terminal {
				node.output = node.output.output
			}
			queue = append(queue, node)
		}
	}
	index.dirty = false
}

// tokenVisible reports whether the token pass can see a name whole rather
// than splitting at an underscore or trimming punctuation off its edges.
func tokenVisible(name string) bool {
	if name == "" || !isAlnum(name[0]) || !isAlnum(name[len(name)-1]) {
		return false
	}
	for i := range len(name) {
		if !isNameByte(name[i]) {
			return false
		}
	}
	return true
}

// matches keeps the longest bounded match at each original byte offset.
// Rune offsets preserve spans when Unicode lower-casing changes byte width.
// After preparation, scanning is linear in text plus matched suffixes, with
// storage bounded by text length even if many names overlap at each position.
func (index *nameIndex) matches(s string) []nameSpan {
	if index.maxDepth == 0 || s == "" {
		return nil
	}
	index.prepare()
	positions := make([]int, min(index.maxDepth, len(s)))
	var ends []int
	node := &index.root
	for offset, pos := 0, 0; offset < len(s); pos++ {
		positions[pos%len(positions)] = offset
		r, size := utf8.DecodeRuneInString(s[offset:])
		r = unicode.ToLower(r)
		offset += size
		for node != &index.root && node.next[r] == nil {
			node = node.fail
		}
		if next := node.next[r]; next != nil {
			node = next
		}
		if offset < len(s) && isAlnum(s[offset]) {
			continue
		}
		match := node
		if !match.terminal {
			match = match.output
		}
		for ; match != nil; match = match.output {
			start := positions[(pos+1-match.depth)%len(positions)]
			if start > 0 && isAlnum(s[start-1]) {
				continue
			}
			if ends == nil {
				ends = make([]int, len(s))
			}
			ends[start] = offset
		}
	}
	var spans []nameSpan
	for start, end := range ends {
		if end > start {
			spans = append(spans, nameSpan{start, end, irregularName})
		}
	}
	return spans
}

type nameSpan struct {
	start, end int
	kind       nameKind
}

type nameKind uint8

const (
	mailName nameKind = iota
	localName
	ipv6Name
	homeName
	irregularName
)

// Only actual output tokens are protected, including when a learned name
// would overlap one. Splitting first also protects a token in a home path
// or mailbox without trusting arbitrary output-shaped input.
func (a *Anonymizer) scrubNames(s string) string {
	var b strings.Builder
	last := 0
	for _, loc := range emittedNameRe.FindAllStringIndex(foldASCII(s), -1) {
		if !bounded(s, loc[0], loc[1]) || !a.isPseudonym(s[loc[0]:loc[1]]) {
			continue
		}
		b.WriteString(a.scrubRawNames(s[last:loc[0]]))
		b.WriteString(s[loc[0]:loc[1]])
		last = loc[1]
	}
	if last == 0 {
		return a.scrubRawNames(s)
	}
	b.WriteString(a.scrubRawNames(s[last:]))
	return b.String()
}

// foldASCII preserves offsets for the ASCII-only emitted-token regex.
func foldASCII(s string) string {
	folded := []byte(s)
	for i, c := range folded {
		if c >= 'A' && c <= 'Z' {
			folded[i] = c + 'a' - 'A'
		}
	}
	return string(folded)
}

func (a *Anonymizer) scrubRawNames(s string) string {
	var spans []nameSpan
	for _, loc := range emailRe.FindAllStringIndex(s, -1) {
		spans = append(spans, nameSpan{loc[0], loc[1], mailName})
	}
	for _, loc := range localPartRe.FindAllStringIndex(s, -1) {
		local := s[loc[0] : loc[1]-1]
		if (loc[0] == 0 || !isAlnum(s[loc[0]-1])) && !systemUsers[local] && !a.isPseudonym(local) {
			spans = append(spans, nameSpan{loc[0], loc[1], localName})
		}
	}
	for _, loc := range ipv6Re.FindAllStringIndex(s, -1) {
		start, end, ok := longestIPv6(s, loc[0], loc[1])
		if ok && !net.ParseIP(s[start:end]).IsLoopback() {
			spans = append(spans, nameSpan{start, end, ipv6Name})
		}
	}
	for _, loc := range homePathRe.FindAllStringIndex(s, -1) {
		spans = append(spans, nameSpan{loc[0], loc[1], homeName})
	}
	spans = append(spans, a.irregular.matches(s)...)
	// Prefer the leftmost complete identity, then the longest span there.
	// A full mailbox wins over its local part, and a whole learned value
	// wins over a mail-shaped fragment inside it. Equal spans keep the
	// existing mailbox/address/path mapping ahead of the generic name map.
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		if spans[i].end != spans[j].end {
			return spans[i].end > spans[j].end
		}
		return spans[i].kind < spans[j].kind
	})
	var b strings.Builder
	last := 0
	for _, span := range spans {
		if span.start < last {
			continue
		}
		b.WriteString(scrubTokens(s[last:span.start], a.token))
		b.WriteString(a.mapNameSpan(s[span.start:span.end], span.kind))
		last = span.end
	}
	if last == 0 {
		return scrubTokens(s, a.token)
	}
	b.WriteString(scrubTokens(s[last:], a.token))
	return b.String()
}

func (a *Anonymizer) mapNameSpan(raw string, kind nameKind) string {
	switch kind {
	case mailName:
		a.counts["emails"]++
		return a.Email(raw)
	case localName:
		a.counts["emails"]++
		return a.remember("user-"+a.label("mailbox", raw[:len(raw)-1])) + "@"
	case ipv6Name:
		a.counts["ipv6"]++
		return a.IPv6(raw)
	case homeName:
		a.counts["accounts"]++
		sub := homePathRe.FindStringSubmatch(raw)
		return sub[1] + a.Account(sub[2])
	default:
		return a.irregularName(raw)
	}
}
