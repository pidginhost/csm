package checks

import "testing"

// These three helpers are unexported pure functions that the broader
// checks package consumes as building blocks. They never get a
// standalone test when their callers are covered at a higher level,
// so they appear at 0% in the merged coverage profile.

func TestCountOccurrences(t *testing.T) {
	cases := []struct {
		name   string
		s      string
		substr string
		want   int
	}{
		{"not present", "hello world", "xyz", 0},
		{"once", "hello world", "world", 1},
		{"overlapping chosen non-greedily", "aaaa", "aa", 2}, // indices 0 and 2
		{"boundary at start", "myfunc(", "myfunc(", 1},
		{"multiple distinct hits", "a.b.c.d", ".", 3},
		{"empty haystack", "", "x", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := countOccurrences(tc.s, tc.substr); got != tc.want {
				t.Errorf("countOccurrences(%q, %q) = %d, want %d", tc.s, tc.substr, got, tc.want)
			}
		})
	}
}

func TestContainsAny(t *testing.T) {
	// Empty slice: nothing to search.
	if containsAny(nil, "x") {
		t.Error("empty strs slice must return false")
	}
	if !containsAny([]string{"hello world", "goodbye"}, "world") {
		t.Error("world is in first string, want true")
	}
	if !containsAny([]string{"hello", "abc123"}, "xyz", "123") {
		t.Error("123 is in second string, want true")
	}
	if containsAny([]string{"hello", "world"}, "xyz", "qux") {
		t.Error("no substring present, want false")
	}
	// No substrs argument: always false (the inner loop never runs).
	if containsAny([]string{"hello"}) {
		t.Error("no substrs: must return false")
	}
}

func TestIsURLWordChar(t *testing.T) {
	yes := []byte{'a', 'z', 'A', 'Z', '0', '9', '_'}
	for _, b := range yes {
		if !isURLWordChar(b) {
			t.Errorf("isURLWordChar(%q) = false, want true", b)
		}
	}
	// The docstring specifies hyphen and slash are NOT word chars; the
	// behaviour of "pharma" matching bounded by "-" relies on this.
	no := []byte{'-', '/', '.', ' ', '?', '\x00'}
	for _, b := range no {
		if isURLWordChar(b) {
			t.Errorf("isURLWordChar(%q) = true, want false", b)
		}
	}
}
