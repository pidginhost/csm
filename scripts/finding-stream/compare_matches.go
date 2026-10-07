package main

import (
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

// pendingRetryAge bounds how long after its preview a scan block can land
// from the legacy pending queue.
const pendingRetryAge = checks.PendingRetryAge

type compareDecision struct {
	kind     string
	capacity uint64
	owners   []int
}

type timedDecision struct {
	at time.Time
	id int
}

// Matching may reassign an earlier block to another compatible decision.
// Greedy consumption can leave a later block unexplained even when both
// have evidence. Summary capacities stay counted rather than expanding
// untrusted counts into one allocation per decision.
func matchComparison(checks map[string]string, legacy []anonAction, steps map[compareStepKey][]time.Time, summaries map[summaryKey]uint64) []string {
	var decisions []compareDecision
	add := func(kind string, n uint64) int {
		decisions = append(decisions, compareDecision{kind: kind, capacity: n})
		return len(decisions) - 1
	}
	stepIDs := map[compareStepKey][]timedDecision{}
	for key, times := range steps {
		for _, at := range times {
			stepIDs[key] = append(stepIDs[key], timedDecision{at, add("step", 1)})
		}
	}
	summaryIDs := map[summaryKey]int{}
	for key, n := range summaries {
		switch key.decision {
		case "coalesced":
			summaryIDs[key] = add("coalesced", n)
		case "refused":
			summaryIDs[key] = add(key.refusal, n)
		}
	}
	choices := make([][]int, len(legacy))
	for i, o := range legacy {
		if o.Action != "permblock" && o.Action != "promote" {
			// A scan block can land from the pending queue until its retry
			// ages out, after the preview observed the first selection.
			earliest := -time.Hour
			if o.ReasonKind == "scan" {
				earliest -= pendingRetryAge
			}
			for _, step := range stepIDs[compareStepKey{o.FindingID, legacyKind(o), o.anonTarget}] {
				if d := step.at.Sub(o.Timestamp); d >= earliest && d <= time.Hour {
					choices[i] = append(choices[i], step.id)
				}
			}
		}
		appendSummaries := func(check, decision, refusal string) {
			end := o.Timestamp.UTC().Truncate(time.Hour).Add(time.Hour)
			for _, at := range []time.Time{end, end.Add(-time.Hour), end.Add(time.Hour)} {
				key := summaryKey{at, check, decision, refusal, legacyEntry(o), legacyKind(o)}
				if id, ok := summaryIDs[key]; ok {
					choices[i] = append(choices[i], id)
				}
			}
		}
		check := checks[o.FindingID]
		if o.FindingID != "" {
			appendSummaries(check, "coalesced", "")
		}
		for _, reason := range designedRefusals {
			if ruleCheck, listed := listedRule(o, check, reason); listed {
				appendSummaries(ruleCheck, "refused", reason)
			}
		}
	}
	matches := make([]string, len(legacy))
	seen := make([]int, len(decisions))
	var assign func(int, int) bool
	assign = func(block, search int) bool {
		for _, id := range choices[block] {
			if seen[id] == search {
				continue
			}
			seen[id] = search
			d := &decisions[id]
			if uint64(len(d.owners)) < d.capacity {
				d.owners = append(d.owners, block)
				matches[block] = d.kind
				return true
			}
			for i, owner := range d.owners {
				if assign(owner, search) {
					d.owners[i] = block
					matches[block] = d.kind
					return true
				}
			}
		}
		return false
	}
	for block := range legacy {
		assign(block, block+1)
	}
	return matches
}
