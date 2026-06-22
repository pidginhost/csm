package checks

import "sort"

// rollingCandidatesAfter selects up to `limit` candidates from the path-sorted,
// de-duplicated `sorted` slice whose path sorts strictly AFTER `lastPath`,
// wrapping once to the start of the list if the end is reached. It returns the
// selected paths (in scan order), the new cursor value (the last selected path,
// to persist as last_path), and whether a wrap occurred during this selection.
//
// Contract:
//   - `sorted` MUST be ascending sorted + de-duplicated (caller guarantees).
//   - lastPath == "" starts from the beginning.
//   - Never returns more than len(sorted) items (one full cycle max), even if
//     limit exceeds len(sorted).
//   - Wrap happens at most once; selection stops when it would revisit the
//     first item of this selection (no infinite loop, no double-scan in a cycle).
//   - limit <= 0 returns (nil, lastPath, false) -- no rolling this cycle.
//   - Empty `sorted` returns (nil, lastPath, false).
//   - newLast is the last path actually selected; if nothing was selected it is
//     lastPath unchanged.
//   - Robust to add/remove between cycles: selection is by VALUE comparison
//     against lastPath (sort.SearchStrings for the first index strictly greater
//     than lastPath), never an integer offset -- a deleted lastPath or inserted
//     earlier file does not corrupt progress.
//
// Documented end-of-list rule for limit >= len(sorted):
//
//	When starting from "" (or any cursor where the pre-wrap tail plus the
//	wrapped head together would cover every element), at most len(sorted) items
//	are returned. If the initial cursor is at the very beginning ("") and the
//	list fits inside limit, the traversal reaches the end without issuing a
//	wrap, so wrapped=false. If the cursor is mid-list and the remaining tail
//	plus the needed head from the wrap together account for all elements,
//	wrapped=true and the selection still caps at len(sorted) with no repeats.
func rollingCandidatesAfter(sorted []string, lastPath string, limit int) (selected []string, newLast string, wrapped bool) {
	if limit <= 0 || len(sorted) == 0 {
		return nil, lastPath, false
	}

	// Cap to one full cycle so we never return duplicates.
	cap := limit
	if cap > len(sorted) {
		cap = len(sorted)
	}

	// Find the first index strictly greater than lastPath.
	// sort.SearchStrings returns the smallest i where sorted[i] >= lastPath.
	// If sorted[i] == lastPath we advance by 1 to get strictly greater.
	start := sort.SearchStrings(sorted, lastPath)
	if start < len(sorted) && sorted[start] == lastPath {
		start++
	}

	selected = make([]string, 0, cap)

	// Phase 1: collect from start to end of sorted.
	i := start
	for len(selected) < cap && i < len(sorted) {
		selected = append(selected, sorted[i])
		i++
	}

	// Phase 2: if we still need more and reached the end, wrap to beginning.
	// Stop before the first item we picked in Phase 1 to avoid repeats.
	if len(selected) < cap && i >= len(sorted) && start > 0 {
		wrapped = true
		j := 0
		// The guard is: j < start (don't revisit items selected in Phase 1)
		// and j < len(selected_from_phase1_start) -- but start is already that
		// boundary since Phase 1 began at `start`.
		for len(selected) < cap && j < start {
			selected = append(selected, sorted[j])
			j++
		}
	} else if len(selected) == 0 && start >= len(sorted) {
		// start was already past the end (e.g. lastPath >= all elements),
		// so wrap unconditionally to the beginning.
		wrapped = true
		j := 0
		for len(selected) < cap && j < len(sorted) {
			selected = append(selected, sorted[j])
			j++
		}
	}

	// Special case: single-element list where lastPath equals the only element.
	// start would be 1 (past end), Phase 2 branch above fires (start=1 >= len=1),
	// so wrapped=true and we return [sorted[0]]. This is handled by the branch above.

	if len(selected) == 0 {
		return nil, lastPath, false
	}
	return selected, selected[len(selected)-1], wrapped
}
