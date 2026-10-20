package learnwatch

import "testing"

func TestPendingReplacementGetsOwnErrorAllowance(t *testing.T) {
	for _, replace := range []bool{false, true} {
		name := "flag_change"
		if replace {
			name = "replacement"
		}
		t.Run(name, func(t *testing.T) {
			f := newState(t)
			f.baselined(t, spamKey)
			f.observe(t, spamKey, "message", meta(200))
			for range MaxEntryErrors - 1 {
				f.do(t, func(tx StateTx) error {
					gaveUp, err := tx.Fail(spamKey, "message")
					if gaveUp {
						t.Error("message exhausted its allowance early")
					}
					return err
				})
			}
			m := meta(200)
			if replace {
				m.Ino++
			}
			if !f.observe(t, spamKey, "message:2,S", m) {
				t.Fatal("pending message disappeared")
			}
			f.do(t, func(tx StateTx) error {
				gaveUp, err := tx.Fail(spamKey, "message")
				if gaveUp == replace {
					t.Errorf("gaveUp=%v for replacement=%v", gaveUp, replace)
				}
				return err
			})
			e, found := f.entry(t, spamKey, "message")
			wantStatus, wantErrors := SkippedStatus(SkipFailed), MaxEntryErrors
			if replace {
				wantStatus, wantErrors = StatusPending, 1
			}
			if !found || e.Status != wantStatus || e.Errors != wantErrors {
				t.Fatalf("replacement=%v: entry %+v", replace, e)
			}
		})
	}
}
