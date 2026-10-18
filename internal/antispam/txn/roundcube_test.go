package txn

import (
	"maps"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

func TestRoundcubeTogglesDoNotReloadServices(t *testing.T) {
	f := newFake(t)
	s := learningApply(f)
	wantOK(t, f.host().Apply(s))
	for _, on := range []bool{true, true, false, false} {
		f.reset()
		s.Roundcube = on
		r := f.host().Apply(s)
		wantOK(t, r)
		want := "<absent>"
		if on {
			want = antispam.RenderRoundcube()
		}
		if f.file(antispam.RoundcubeIncludePath) != want {
			t.Fatalf("Roundcube on=%t: include does not match", on)
		}
		if f.file(antispam.RecordPath) != string(antispam.EncodeRecord(r.Generation)) {
			t.Fatal("completion record does not match the result")
		}
		if f.count("systemctl reload") != 0 || f.count(BuildEximConf) != 0 {
			t.Fatal("Roundcube toggle reloaded a service or rebuilt Exim")
		}
	}
}

func TestRoundcubeTransactionRollback(t *testing.T) {
	for _, operation := range []string{"install", "enable", "disable", "remove"} {
		for _, failure := range []string{"include", "completion"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				f := newFake(t)
				s := learningApply(f)
				s.Roundcube = operation == "disable" || operation == "remove"
				if operation != "install" {
					wantOK(t, f.host().Apply(s))
				}
				before := f.state()
				f.reset()
				s.Roundcube = operation != "disable"
				h := f.host()
				failed := false
				h.replace = func(p string, want, next fileState) error {
					if err := replaceFile(p, want, next); err != nil {
						return err
					}
					include := p == f.root+antispam.RoundcubeIncludePath
					complete := p == f.root+antispam.RecordPath && next.content != string(antispam.EncodeRecord(""))
					if !failed && (failure == "include" && include || failure == "completion" && complete) {
						failed = true
						return errDurability
					}
					return nil
				}
				var r antispam.Result
				if operation == "remove" {
					r = h.Remove()
				} else {
					r = h.Apply(s)
				}
				step := StepRoundcube
				if failure == "completion" {
					step = StepComplete
				}
				if !failed || r.OK || r.FailedStep != step || r.Rollback != antispam.RollbackVerified {
					t.Fatalf("result %+v, failure injected=%t", r, failed)
				}
				if !maps.Equal(f.state(), before) {
					t.Fatal("rollback did not restore every target and the completion record")
				}
				if operation == "enable" || operation == "disable" {
					if f.count("systemctl reload") != 0 || f.count(BuildEximConf) != 0 {
						t.Fatal("include-only rollback reloaded a service or rebuilt Exim")
					}
				}
			})
		}
	}
}
