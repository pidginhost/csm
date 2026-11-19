package admissionowner

import (
	"errors"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/firewall"
)

// observeBlockBatch counts the engine call once, before outcome persistence
// can retry. A short reply cannot prove which members applied; unknown
// outcomes must never advertise a healthy block path.
func observeBlockBatch(picks []execPick, run []int, results []firewall.BlockResult, err error) {
	if err == nil && len(results) != len(run) {
		err = errors.New("incomplete block batch reply")
	}
	for i, index := range run {
		entry := picks[index].c.Entry
		if err != nil {
			checks.ObserveAdmissionBlock(entry, firewall.BlockOutcomeNoop, err)
			continue
		}
		r := results[i]
		switch {
		case r.Err != nil:
			checks.ObserveAdmissionBlock(entry, firewall.BlockOutcomeNoop, r.Err)
		case r.Effect == firewall.BlockApplied:
			checks.ObserveAdmissionBlock(entry, firewall.BlockOutcomeLive, nil)
		case r.Effect == firewall.BlockFailed && r.Refusal != "":
			observeBlockRefusal(entry, r.Refusal)
		default:
			checks.ObserveAdmissionBlock(entry, firewall.BlockOutcomeNoop, errors.New("block outcome is unproven"))
		}
	}
}

func observeBlockRefusal(entry admission.Entry, refusal firewall.BlockRefusal) {
	outcome := firewall.BlockOutcomeNoop
	var err error
	switch refusal {
	case firewall.BlockRefusedProtected:
		err = firewall.ErrIPProtected
	case firewall.BlockRefusedAllowed:
		outcome = firewall.BlockOutcomeAllowlisted
	}
	checks.ObserveAdmissionBlock(entry, outcome, err)
}
