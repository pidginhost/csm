package learn

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/pidginhost/csm/internal/store"
)

// Status is what the ledger holds for one operator request ID: its
// recorded outcome and, for clusters still publishing, their phase.
type Status struct {
	RequestID           string
	Action              string
	Found, Done, ExitOK bool
	Outcome             string
	Digests             []Digest
	Clusters            []StatusCluster
}

// StatusCluster is one cluster's recorded result; Phase is set while its
// publication is unfinished.
type StatusCluster struct {
	ClusterID uint64
	Result    string
	Phase     Phase
}

// RequestStatus reads the given request IDs, or every unfinished request
// when ids is empty (spec 8). It only reads, so it is safe beside a running
// engine and when none runs.
func RequestStatus(l *Ledger, ids []string) ([]Status, error) {
	var out []Status
	err := l.View(func(v LedgerView) error {
		if len(ids) == 0 {
			if err := v.tx.ForEach(store.LearnOpsBucket, func(k, data []byte) error {
				var o OpRecord
				if err := json.Unmarshal(data, &o); err != nil {
					return errors.New("learning ledger request record is unreadable")
				}
				if !o.Done {
					ids = append(ids, string(k))
				}
				return nil
			}); err != nil {
				return err
			}
		}
		for _, id := range ids {
			s, err := requestStatus(v, id)
			if err != nil {
				return err
			}
			out = append(out, s)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	return out, nil
}

func requestStatus(v LedgerView, id string) (Status, error) {
	s := Status{RequestID: id}
	o, ok, err := v.Op(id)
	if err != nil || !ok {
		return s, err
	}
	s.Action, s.Found, s.Done = o.Action, true, o.Done
	if o.Outcome == nil {
		return s, nil
	}
	s.Outcome, s.ExitOK, s.Digests = o.Outcome.Outcome, o.Outcome.ExitOK, o.Outcome.Digests
	intent, _, err := v.Intent(id)
	if err != nil {
		return s, err
	}
	for _, c := range o.Outcome.Clusters {
		sc := StatusCluster{ClusterID: c.ClusterID, Result: c.Result}
		if c.Result == ResultPending {
			for _, ic := range intent.Clusters {
				if ic.ClusterID != c.ClusterID || ic.Done {
					continue
				}
				t, found, err := v.Target(ic.Anchor)
				if err != nil {
					return s, err
				}
				if found {
					sc.Phase = t.Phase
				}
			}
		}
		s.Clusters = append(s.Clusters, sc)
	}
	return s, nil
}
