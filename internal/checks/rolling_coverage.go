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
	maxCount := limit
	if maxCount > len(sorted) {
		maxCount = len(sorted)
	}

	// Find the first index strictly greater than lastPath.
	// sort.SearchStrings returns the smallest i where sorted[i] >= lastPath.
	// If sorted[i] == lastPath we advance by 1 to get strictly greater.
	start := sort.SearchStrings(sorted, lastPath)
	if start < len(sorted) && sorted[start] == lastPath {
		start++
	}

	selected = make([]string, 0, maxCount)

	// Phase 1: collect from start to end of sorted.
	i := start
	for len(selected) < maxCount && i < len(sorted) {
		selected = append(selected, sorted[i])
		i++
	}

	// Phase 2: if we still need more and reached the end, wrap to the beginning.
	// Stop before `start` so we never revisit a Phase-1 item (no repeats). This
	// also covers a cursor at/after the last element (start >= len(sorted) with
	// start > 0, e.g. lastPath == max or a single-element list): Phase 1 collects
	// nothing and the wrap re-covers from the head.
	if len(selected) < maxCount && i >= len(sorted) && start > 0 {
		wrapped = true
		for j := 0; len(selected) < maxCount && j < start; j++ {
			selected = append(selected, sorted[j])
		}
	}

	if len(selected) == 0 {
		return nil, lastPath, false
	}
	return selected, selected[len(selected)-1], wrapped
}
