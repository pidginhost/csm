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
// Steps share one budget across runs, including retries after a restart.
// Summary counts belong only to the run that recorded them.
// Greedy consumption can leave a later block unexplained even when both
// have evidence. Summary capacities stay counted rather than expanding
// untrusted counts into one allocation per decision.
func matchComparisons(checks map[string]string, runs []*compareRun, steps map[compareStepKey][]time.Time) {
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
	var choices [][]int
	runChoices := map[*compareRun][][]int{}
	// Adjacent runs can include the same boundary hour. Match each input
	// row once even when it appears in both reports.
	blocks := map[int]int{}
	for _, run := range runs {
		summaryIDs := map[summaryKey]int{}
		for key, n := range run.summaries {
			switch key.decision {
			case "coalesced":
				summaryIDs[key] = add("coalesced", n)
			case "refused":
				summaryIDs[key] = add(key.refusal, n)
			}
		}
		for _, block := range run.legacy {
			o := block.anonAction
			i, exists := blocks[block.row]
			if !exists {
				i = len(choices)
				blocks[block.row] = i
				choices = append(choices, nil)
			}
			if !exists && o.Action != "permblock" && o.Action != "promote" {
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
			var summaryChoices []int
			appendSummaries := func(check, decision, refusal string) {
				end := o.Timestamp.UTC().Truncate(time.Hour).Add(time.Hour)
				for _, at := range []time.Time{end, end.Add(-time.Hour), end.Add(time.Hour)} {
					key := summaryKey{at, check, decision, refusal, legacyEntry(o), legacyKind(o)}
					if id, ok := summaryIDs[key]; ok {
						choices[i] = append(choices[i], id)
						summaryChoices = append(summaryChoices, id)
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
			runChoices[run] = append(runChoices[run], summaryChoices)
		}
	}
	matches := matchDecisions(choices, decisions)
	for _, run := range runs {
		run.matches = make([]string, len(run.legacy))
		local := runChoices[run]
		for i, block := range run.legacy {
			if d := matches[blocks[block.row]]; d != nil && d.kind == "step" {
				run.matches[i] = d.kind
				local[i] = nil
			}
		}
		// Fix the shared step allocation, then spend each run's summaries
		// on its remaining rows. A shared boundary row can be explained by
		// a separate aggregate count in each run, but cannot borrow one.
		for i, d := range matchDecisions(local, decisions) {
			if d != nil {
				run.matches[i] = d.kind
			}
		}
	}
	// A restart mid-hour puts the old process's blocks of that hour in the
	// new run's window too. One the old run's own summaries explain is
	// explained here as well, but adds no coverage to this run. A step is
	// one decision per row, so a row a step matched is matched in every run.
	explained := map[int]bool{}
	for _, run := range runs {
		for i, block := range run.legacy {
			if d := run.matches[i]; d != "" && d != otherRun {
				explained[block.row] = true
			}
		}
	}
	for _, run := range runs {
		for i, block := range run.legacy {
			if run.matches[i] == "" && explained[block.row] {
				run.matches[i] = otherRun
			}
		}
	}
}

// otherRun marks a block another run's summaries explain.
const otherRun = "other run"

func matchDecisions(choices [][]int, decisions []compareDecision) []*compareDecision {
	for i := range decisions {
		decisions[i].owners = nil
	}
	matches := make([]*compareDecision, len(choices))
	seen := make([]int, len(decisions))
	var assign func(int, int, bool) bool
	assign = func(block, search int, refusals bool) bool {
		for _, id := range choices[block] {
			d := &decisions[id]
			if !refusals && d.kind != "step" && d.kind != "coalesced" {
				continue
			}
			if seen[id] == search {
				continue
			}
			seen[id] = search
			if uint64(len(d.owners)) < d.capacity {
				d.owners = append(d.owners, block)
				matches[block] = d
				return true
			}
			for i, owner := range d.owners {
				if assign(owner, search, refusals) {
					d.owners[i] = block
					matches[block] = d
					return true
				}
			}
		}
		return false
	}
	// Refusals explain discrepancies but cannot establish coverage. Find
	// the largest observed match first; augmenting it with refusals keeps
	// those decisions occupied while explaining any remaining blocks.
	search := 0
	for _, refusals := range []bool{false, true} {
		for block := range choices {
			if matches[block] == nil {
				search++
				assign(block, search, refusals)
			}
		}
	}
	return matches
}
