package checks

import (
	"testing"
)

// TestRollingCandidatesAfter covers all 10 spec cases from task-D3-brief.md.
func TestRollingCandidatesAfter(t *testing.T) {
	abcd := []string{"a", "b", "c", "d"}

	t.Run("fresh_start", func(t *testing.T) {
		// Case 1: empty lastPath starts from beginning.
		sel, newLast, wrapped := rollingCandidatesAfter(abcd, "", 2)
		if len(sel) != 2 || sel[0] != "a" || sel[1] != "b" {
			t.Errorf("expected [a b], got %v", sel)
		}
		if newLast != "b" {
			t.Errorf("expected newLast=b, got %q", newLast)
		}
		if wrapped {
			t.Error("expected wrapped=false")
		}
	})

	t.Run("mid_list", func(t *testing.T) {
		// Case 2: advance from mid-list cursor.
		sel, newLast, wrapped := rollingCandidatesAfter(abcd, "b", 2)
		if len(sel) != 2 || sel[0] != "c" || sel[1] != "d" {
			t.Errorf("expected [c d], got %v", sel)
		}
		if newLast != "d" {
			t.Errorf("expected newLast=d, got %q", newLast)
		}
		if wrapped {
			t.Error("expected wrapped=false")
		}
	})

	t.Run("wrap_at_tail", func(t *testing.T) {
		// Case 3: cursor near end, wraps to start.
		sel, newLast, wrapped := rollingCandidatesAfter(abcd, "c", 2)
		if len(sel) != 2 || sel[0] != "d" || sel[1] != "a" {
			t.Errorf("expected [d a], got %v", sel)
		}
		if newLast != "a" {
			t.Errorf("expected newLast=a, got %q", newLast)
		}
		if !wrapped {
			t.Error("expected wrapped=true")
		}
	})

	t.Run("cursor_past_end", func(t *testing.T) {
		// Case 4: lastPath beyond all sorted values -> wrap to start.
		sel, newLast, wrapped := rollingCandidatesAfter(abcd, "d", 2)
		if len(sel) != 2 || sel[0] != "a" || sel[1] != "b" {
			t.Errorf("expected [a b], got %v", sel)
		}
		if newLast != "b" {
			t.Errorf("expected newLast=b, got %q", newLast)
		}
		if !wrapped {
			t.Error("expected wrapped=true")
		}
	})

	t.Run("deleted_cursor_file", func(t *testing.T) {
		// Case 5: cursor file was removed from sorted; first > "c" is "d".
		sorted := []string{"a", "b", "d"}
		sel, newLast, wrapped := rollingCandidatesAfter(sorted, "c", 2)
		if len(sel) != 2 || sel[0] != "d" || sel[1] != "a" {
			t.Errorf("expected [d a], got %v", sel)
		}
		if newLast != "a" {
			t.Errorf("expected newLast=a, got %q", newLast)
		}
		if !wrapped {
			t.Error("expected wrapped=true")
		}
	})

	t.Run("added_file_before_cursor_eventually_covered", func(t *testing.T) {
		// Case 6: "a2" inserted before cursor; drive 2 calls, union must cover all.
		sorted := []string{"a", "a2", "b", "c", "d"}
		// First call: lastPath="c", limit=2 -> picks d then wraps to a.
		sel1, last1, wrapped1 := rollingCandidatesAfter(sorted, "c", 2)
		if len(sel1) != 2 || sel1[0] != "d" || sel1[1] != "a" {
			t.Errorf("call1: expected [d a], got %v", sel1)
		}
		if !wrapped1 {
			t.Error("call1: expected wrapped=true")
		}
		// Second call: lastPath="a", limit=2 -> picks a2 then b.
		sel2, last2, wrapped2 := rollingCandidatesAfter(sorted, last1, 2)
		if len(sel2) != 2 || sel2[0] != "a2" || sel2[1] != "b" {
			t.Errorf("call2: expected [a2 b], got %v", sel2)
		}
		if wrapped2 {
			t.Error("call2: expected wrapped=false")
		}
		_ = last2
		// Verify union covers all 5 paths.
		// "c" was the initial lastPath (already scanned before these calls),
		// so the full coverage includes it as the prior cursor.
		covered := make(map[string]bool)
		covered["c"] = true // initial cursor = already scanned
		for _, p := range sel1 {
			covered[p] = true
		}
		for _, p := range sel2 {
			covered[p] = true
		}
		for _, p := range sorted {
			if !covered[p] {
				t.Errorf("path %q not covered across two calls (plus initial cursor)", p)
			}
		}
	})

	t.Run("limit_exceeds_len", func(t *testing.T) {
		// Case 7: limit >= len -> return at most len items, each exactly once.
		// Documented behavior: when starting from "" (beginning), we scan forward
		// and never wrap past where we started, so we return exactly [a,b,c]
		// without repeating any item. wrapped=false because we reached the end
		// of the list without needing a wrap (the full list fits in limit).
		sorted := []string{"a", "b", "c"}
		sel, newLast, wrapped := rollingCandidatesAfter(sorted, "", 10)
		if len(sel) != 3 {
			t.Errorf("expected 3 items, got %d: %v", len(sel), sel)
		}
		if len(sel) >= 1 && sel[0] != "a" {
			t.Errorf("expected sel[0]=a, got %q", sel[0])
		}
		if len(sel) >= 2 && sel[1] != "b" {
			t.Errorf("expected sel[1]=b, got %q", sel[1])
		}
		if len(sel) >= 3 && sel[2] != "c" {
			t.Errorf("expected sel[2]=c, got %q", sel[2])
		}
		if newLast != "c" {
			t.Errorf("expected newLast=c, got %q", newLast)
		}
		if wrapped {
			t.Error("expected wrapped=false (full list fits without wrap)")
		}
		// Verify no duplicates.
		seen := make(map[string]bool)
		for _, p := range sel {
			if seen[p] {
				t.Errorf("duplicate path %q in selection", p)
			}
			seen[p] = true
		}
	})

	t.Run("limit_zero", func(t *testing.T) {
		// Case 8: limit=0 -> nil, unchanged lastPath, false.
		sel, newLast, wrapped := rollingCandidatesAfter(abcd, "b", 0)
		if sel != nil {
			t.Errorf("expected nil selection, got %v", sel)
		}
		if newLast != "b" {
			t.Errorf("expected newLast unchanged=b, got %q", newLast)
		}
		if wrapped {
			t.Error("expected wrapped=false")
		}
	})

	t.Run("empty_sorted", func(t *testing.T) {
		// Case 9: empty sorted -> nil, unchanged lastPath, false.
		sel, newLast, wrapped := rollingCandidatesAfter(nil, "z", 5)
		if sel != nil {
			t.Errorf("expected nil selection, got %v", sel)
		}
		if newLast != "z" {
			t.Errorf("expected newLast unchanged=z, got %q", newLast)
		}
		if wrapped {
			t.Error("expected wrapped=false")
		}
	})

	t.Run("single_element_cursor_equals_it", func(t *testing.T) {
		// Case 10: single element, lastPath == it -> wrap returns [a], wrapped=true.
		sorted := []string{"a"}
		sel, newLast, wrapped := rollingCandidatesAfter(sorted, "a", 5)
		if len(sel) != 1 || sel[0] != "a" {
			t.Errorf("expected [a], got %v", sel)
		}
		if newLast != "a" {
			t.Errorf("expected newLast=a, got %q", newLast)
		}
		if !wrapped {
			t.Error("expected wrapped=true")
		}
	})
}
