package phptaint

import "bytes"

// sinkKeywords and sourceKeywords drive admission only. They are language
// constructs and library function names, never variable or file names.
var (
	sinkKeywords = [][]byte{
		[]byte("eval"), []byte("include"), []byte("require"),
		[]byte("assert"), []byte("create_function"),
	}
	sourceKeywords = [][]byte{
		[]byte("curl_exec"), []byte("curl_multi_getcontent"),
		[]byte("file_get_contents"), []byte("fopen"), []byte("fread"),
		[]byte("fgets"), []byte("stream_get_contents"), []byte("readfile"),
		[]byte("wp_remote_retrieve_body"), []byte("wp_remote_get"),
		[]byte("fsockopen"),
	}
	phpOpenTags = [][]byte{[]byte("<?php"), []byte("<?="), []byte("<?")}
)

// foldChunkBytes bounds the lowercased working copy containsAnyFold folds
// src into. Matching case-insensitively requires comparing against a
// lowercased view of the bytes somewhere; the previous implementation
// lowercased the entire file up front, which meant a full-size allocation
// and copy for every file scanned, paid even on the reject path -- the hot
// path for a daemon walking millions of files, most of which are not PHP at
// all. Folding a small fixed-size window at a time bounds that cost to a
// constant instead of MaxSourceBytes. 64KiB is also small enough that the
// compiler keeps the working buffer on the stack rather than the heap, so
// this costs zero allocations, not just a smaller one.
const foldChunkBytes = 64 << 10

// maxNeedleBytes is the longest literal in sinkKeywords, sourceKeywords, or
// phpOpenTags, computed rather than hand-maintained so a future longer
// keyword cannot silently undersize the window overlap below and reopen a
// false negative. Consecutive folded windows overlap by this many bytes
// minus one so a match straddling a window boundary is never missed.
var maxNeedleBytes = longestNeedle(sinkKeywords, sourceKeywords, phpOpenTags)

func longestNeedle(groups ...[][]byte) int {
	max := 0
	for _, group := range groups {
		for _, n := range group {
			if len(n) > max {
				max = len(n)
			}
		}
	}
	return max
}

// isCandidate is a cheap byte scan run before parsing. It is intentionally
// over-inclusive; the AST pass decides whether a real flow exists. PHP
// function names and language constructs are case-insensitive (EVAL, Eval
// and eval all execute the same construct), so admission matches
// case-insensitively too, on pain of a false negative admitting less than
// the AST rules would. The open-tag check runs first so a file that never
// looks like PHP never pays for the sink/source keyword scans either.
// MayBePHPSource reports whether content could be PHP at all, judged only by
// the presence of an open tag. It exists for callers that must decide
// something about a file they cannot analyze in full -- an oversize file, say
// -- and would otherwise have to guess.
//
// It is deliberately weaker than isCandidate: no sink or source keyword is
// required, because a caller holding only a prefix cannot conclude anything
// from their absence. Judging by content rather than by name or extension is
// the point; a scanner that decided what to examine from a path would be
// telling an attacker where to hide.
func MayBePHPSource(prefix []byte) bool {
	return containsAnyFold(prefix, phpOpenTags)
}

func isCandidate(src []byte) bool {
	if !containsAnyFold(src, phpOpenTags) {
		return false
	}
	return containsAnyFold(src, sinkKeywords) && containsAnyFold(src, sourceKeywords)
}

// containsAnyFold reports whether any needle occurs in hay under ASCII case
// folding. It folds hay one bounded window at a time into a stack-local
// buffer -- never allocating a lowercased copy of the whole input -- and
// runs the standard library's optimized bytes.Contains against each folded
// window, so search speed stays close to a plain bytes.Contains scan.
// Windows overlap by maxNeedleBytes-1 bytes so a needle split across a
// window boundary still lands whole inside the next window.
func containsAnyFold(hay []byte, needles [][]byte) bool {
	if len(hay) == 0 {
		return false
	}
	overlap := maxNeedleBytes - 1
	step := foldChunkBytes - overlap
	var buf [foldChunkBytes]byte
	for start := 0; start < len(hay); start += step {
		end := start + foldChunkBytes
		if end > len(hay) {
			end = len(hay)
		}
		window := hay[start:end]
		folded := buf[:len(window)]
		for i, b := range window {
			folded[i] = lowerASCII(b)
		}
		for _, n := range needles {
			if bytes.Contains(folded, n) {
				return true
			}
		}
		if end == len(hay) {
			break
		}
	}
	return false
}

func lowerASCII(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
