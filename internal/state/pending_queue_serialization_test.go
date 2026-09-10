package state

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/atomicio"
)

func TestPendingQueueSerializedIdentity(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		label := "valid_replacement"
		detail := "fixture replacement \ufffd"
		if invalid {
			label = "invalid_utf8"
			detail = "fixture replacement " + string([]byte{0xff})
		}
		t.Run(label, func(t *testing.T) {
			for _, committedError := range []bool{false, true} {
				outcome := "success"
				if committedError {
					outcome = "committed_error"
				}
				t.Run(outcome, func(t *testing.T) {
					st, openErr := Open(t.TempDir())
					if openErr != nil {
						t.Fatal(openErr)
					}
					if err := st.AppendPendingFindings(make([]alert.Finding, pendingFindingsMax)); err != nil {
						t.Fatal(err)
					}
					incoming := make([]alert.Finding, 3)
					for i := range incoming {
						incoming[i] = alert.Finding{Check: "fixture", Details: detail}
					}
					encoded, encodeErr := json.Marshal(incoming)
					if encodeErr != nil {
						t.Fatal(encodeErr)
					}
					var expected []alert.Finding
					if err := json.Unmarshal(encoded, &expected); err != nil {
						t.Fatal(err)
					}
					sentinel := errors.New("fixture returned error after durable replacement")
					if committedError {
						st.writePendingFile = func(path string, mode os.FileMode, value any) error {
							if err := atomicio.AtomicWriteJSON(path, mode, value); err != nil {
								return err
							}
							return sentinel
						}
					}
					err := st.AppendPendingFindings(incoming)
					if committedError && err != sentinel || !committedError && err != nil {
						t.Fatalf("changed returned error policy: %v", err)
					}
					row := st.QueueStatuses(time.Now())["pending"]
					if row.Depth != pendingFindingsMax || row.InFlight != 0 || row.DroppedTotal != 3 || row.DroppedLowerBound || row.DepthUnavailable {
						t.Errorf("confirmed physical replacement and exactly three overflow losses: %+v", row)
					}
					got, err := st.TakePendingFindings()
					if err != nil {
						t.Fatal(err)
					}
					if len(got) != pendingFindingsMax {
						t.Fatalf("physical retained count=%d", len(got))
					}
					for _, f := range got[len(got)-3:] {
						if f.Check != "fixture" || f.Details != expected[0].Details {
							t.Error("physical retained payload mismatch")
						}
					}
					row = st.QueueStatuses(time.Now().Add(2 * time.Minute))["pending"]
					if row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 3 || row.DroppedLowerBound || row.DepthUnavailable || row.Status != "ok" {
						t.Errorf("successful read and clear must preserve exact accounting: %+v", row)
					}
				})
			}
		})
	}
}
