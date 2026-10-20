package txn

import (
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

func TestRollbackKeepsLearningSecretsPrivate(t *testing.T) {
	for _, target := range []string{antispam.LearningCheckPath, antispam.LearningWorkerPath} {
		t.Run(target, func(t *testing.T) {
			f := newFake(t)
			s := learningApply(f)
			wantOK(t, f.host().Apply(s))
			prior, readErr := readFile(f.root + target)
			if readErr != nil {
				t.Fatal(readErr)
			}
			f.reset()
			f.learning.Read, f.learning.Write = f.learning.Write, f.learning.Read
			f.fail["rspamadm configtest"] = []int{1}
			f.onCall = func(line string) {
				if line == "rspamadm configtest" {
					if err := os.Chmod(f.root+target, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			r := f.host().Apply(s)
			if r.OK || r.FailedStep != StepRspamdCheck || r.Rollback != antispam.RollbackVerified {
				t.Fatalf("result %+v", r)
			}
			got, err := readFile(f.root + target)
			if err != nil || !sameContent(got, prior) || got.perm != antispam.SecretFileMode || got.gid != prior.gid || got.uid != prior.uid {
				t.Fatalf("rollback privacy: content restored=%t mode=%v owner restored=%t error=%v",
					sameContent(got, prior), got.perm, got.uid == prior.uid && got.gid == prior.gid, err)
			}
		})
	}
}

func TestLearningAndRoundcubeDriftReloadOnlyRspamdTargets(t *testing.T) {
	for _, target := range append(antispam.LearningPaths(), antispam.RoundcubeIncludePath) {
		for _, missing := range []bool{false, true} {
			t.Run(target+map[bool]string{false: "/edited", true: "/missing"}[missing], func(t *testing.T) {
				f := newFake(t)
				s := learningApply(f)
				s.Roundcube = true
				wantOK(t, f.host().Apply(s))
				before := f.state()
				if missing {
					if err := os.Remove(f.root + target); err != nil {
						t.Fatal(err)
					}
				} else {
					comment := "# local edit\n"
					if target == antispam.LearningLuaPath {
						comment = "-- local edit\n"
					}
					writeTest(t, f.root+target, before[target]+comment, 0o644)
				}
				f.reset()
				wantOK(t, f.host().Apply(s))
				if f.file(target) != before[target] || f.file(antispam.RecordPath) != before[antispam.RecordPath] {
					t.Fatal("drift repair did not restore the completed content")
				}
				wantRspamd := 1
				if target == antispam.RoundcubeIncludePath {
					wantRspamd = 0
				}
				if f.count(BuildEximConf) != 0 || f.count("systemctl reload exim.service") != 0 ||
					f.count("systemctl reload rspamd.service") != wantRspamd {
					t.Fatalf("drift repair: builds=%d Exim reloads=%d rspamd reloads=%d, want 0/0/%d",
						f.count(BuildEximConf), f.count("systemctl reload exim.service"), f.count("systemctl reload rspamd.service"), wantRspamd)
				}
			})
		}
	}
}
