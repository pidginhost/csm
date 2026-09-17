//go:build linux

package store

import (
	"errors"
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

type changingPlanningStore struct {
	*DB
	onRead   func(firewall.FirewallState, uint64) error
	admitted []firewall.FirewallAction
}

func (s *changingPlanningStore) ReadFirewallState() (firewall.FirewallState, uint64, error) {
	state, revision, err := s.DB.ReadFirewallState()
	if err != nil {
		return state, revision, err
	}
	if hook := s.onRead; hook != nil {
		s.onRead = nil
		if hookErr := hook(state, revision); hookErr != nil {
			return firewall.FirewallState{}, 0, hookErr
		}
	}
	return state, revision, nil
}

func (s *changingPlanningStore) AdmitFirewallAction(plan firewall.FirewallAction) (firewall.FirewallAction, bool, error) {
	action, fresh, err := s.DB.AdmitFirewallAction(plan)
	if fresh {
		s.admitted = append(s.admitted, action)
	}
	return action, fresh, err
}

func TestFirewallLifecyclePlanningRejectsStaleState(t *testing.T) {
	readFailure := errors.New("planning read unavailable")
	for _, tc := range []struct {
		name    string
		readErr error
		wantErr error
	}{
		{name: "new revision after planning read", wantErr: firewall.ErrStateConflict},
		{name: "planning read fails with warm cache", readErr: readFailure, wantErr: readFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := openSnapshotDB(t)
			initial := firewall.FirewallState{PortAllowed: []firewall.PortAllowEntry{{IP: "192.0.2.101", Port: 443, Proto: "tcp", Reason: "existing policy"}}}
			if _, err := db.ReplaceFirewallState(0, initial); err != nil {
				t.Fatal(err)
			}
			s := &changingPlanningStore{DB: db}
			engine, err := firewall.NewEngine(&firewall.FirewallConfig{}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err = engine.AttachLifecycle(&firewall.Lifecycle{Store: s, Audit: func(firewall.FirewallAction) error { return nil }}); err != nil {
				t.Fatal(err)
			}
			var concurrent firewall.FirewallState
			var committedRevision uint64
			s.onRead = func(state firewall.FirewallState, revision uint64) error {
				// A separate writer commits after the engine's planning snapshot
				// was read, before that snapshot can be admitted for mutation.
				concurrent = state
				concurrent.PortAllowed = append(concurrent.PortAllowed, firewall.PortAllowEntry{IP: "192.0.2.102", Port: 8443, Proto: "tcp", Reason: "concurrent policy"})
				var commitErr error
				committedRevision, commitErr = db.ReplaceFirewallState(revision, concurrent)
				if commitErr != nil {
					t.Fatal(commitErr)
				}
				return tc.readErr
			}
			err = engine.AllowIPPort("192.0.2.103", 9443, "tcp", "new policy")
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("stale planning result = %v, want %v", err, tc.wantErr)
			}
			actual, revision, stateErr := db.ReadFirewallState()
			if stateErr != nil || revision != committedRevision || !reflect.DeepEqual(actual, concurrent) {
				t.Errorf("concurrent policy lost: state=%+v revision=%d error=%v, want state=%+v revision=%d", actual, revision, stateErr, concurrent, committedRevision)
			}
			if len(s.admitted) != 0 {
				t.Errorf("stale plan was admitted: %+v", s.admitted)
			}
		})
	}
}
