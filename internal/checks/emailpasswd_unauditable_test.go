package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
)

// A hash this build cannot audit - an unsupported scheme, a malformed record,
// or a work factor past the budget - never becomes auditable by rerunning.
// Counting those as "unfinished" held the refresh stamp back forever, so the
// whole mailbox set was re-verified on every scan instead of on its interval.
func TestUnauditableHashesAreNotRetryable(t *testing.T) {
	for name, err := range map[string]error{
		"unsupported scheme": errEmailHashUnsupported,
		"malformed record":   errEmailHashInvalid,
		"work factor":        errEmailHashCost,
	} {
		if !emailHashPermanentlyUnauditable(err) {
			t.Errorf("%s is treated as retryable, so it blocks the refresh stamp forever", name)
		}
	}
}

// A transient failure may succeed next time, so it must still hold the stamp.
func TestTransientFailuresRemainRetryable(t *testing.T) {
	if emailHashPermanentlyUnauditable(errors.New("connection reset")) {
		t.Fatal("a transient failure was treated as permanently unauditable")
	}
}

func TestWrappedHashFailuresRemainRetryable(t *testing.T) {
	for _, sentinel := range []error{errEmailHashUnsupported, errEmailHashInvalid, errEmailHashCost} {
		for _, err := range []error{
			fmt.Errorf("temporary verification failure: %w", sentinel),
			&os.PathError{Op: "read", Path: "shadow", Err: sentinel},
			errors.Join(context.DeadlineExceeded, sentinel),
			errors.Join(sentinel, context.Canceled),
		} {
			if emailHashPermanentlyUnauditable(err) {
				t.Errorf("wrapped failure %v must remain retryable", err)
			}
		}
	}
}
