package main

import (
	"os"
	"slices"
	"testing"
)

// A successful inventory must require evidence for the work behind the
// eval-site semaphore and result channel, in both production runner modes.
func TestPHPShieldEvalQueueRequiresEvidence(t *testing.T) {
	root := os.DirFS("../..")
	var manifest queueManifest
	if err := decodeFile(root, "scripts/queue-inventory.json", &manifest); err != nil {
		t.Fatal(err)
	}
	evidence, err := validateManifest(root, manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"portable", "kernel"} {
		required, err := requiredTests(evidence, nil, mode)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{
			"TestPHPShieldEvalSiteQueuePublished",
			"TestPHPShieldEvalSiteQueueRetainsTimedOutLookup",
			"TestPHPShieldEvalSiteQueueRetainsUndeliveredResult",
			"TestPHPShieldEvalSiteQueueAbnormalWalkSettlesOnce",
			"TestPHPShieldEvalSiteTimeoutNeedsOnlyOneWorker",
			"TestPHPShieldEvalSiteBackToBackEventsAreEachProven",
			"TestPHPShieldEvalFatalOutsideRootOwnedCodeStaysHigh",
			"TestPHPShieldEvalFatalWarningDoesNotDedupHigh",
		} {
			if !slices.Contains(required, requiredTest{Package: modulePath + "/internal/daemon", Name: name}) {
				t.Errorf("%s gate does not require %s", mode, name)
			}
		}
	}
	for _, decision := range manifest.Allocations {
		if decision.Path == "internal/daemon/php_events_eval_site.go" && (decision.Class != "work" || decision.Queue != "php_shield.eval_sites") {
			t.Errorf("eval-site protection work has no work owner: %+v", decision)
		}
	}
}
