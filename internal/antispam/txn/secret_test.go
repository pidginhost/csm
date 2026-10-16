package txn

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

const otherKey = "zyxwvutsrqponmlkjihgf65432"

// dqsApply sets f up for a DQS apply whose rbl rules load as rendered.
func dqsApply(f *fakeHost) antispam.Settings {
	f.modules = "Modules enabled: dkim, spf, rbl\n"
	f.rbl = `{"rbls":{"csm_dqs_zen":{},"csm_dqs_dbl":{},"csm_dqs_zrd":{}}}`
	s := enforce()
	s.Feeds, s.DQSKeyFile = []string{antispam.FeedSpamhausDQS}, "/etc/csm/k"
	return s
}

func TestApplyFeedCheckDoesNotExposeDQSKey(t *testing.T) {
	key := f0Key()
	for _, commandFailed := range []bool{false, true} {
		f := newFake(t)
		s := dqsApply(f)
		h := f.host()
		run := h.run
		h.run = func(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
			if name == "rspamadm" && strings.Join(args, " ") == "configdump -j rbl" {
				r := antispam.CommandResult{Stdout: key, Stderr: key}
				if commandFailed {
					r.Err = errors.New(key)
				}
				return r
			}
			return run(ctx, limit, name, args...)
		}
		want := StepFeedsCheck
		if commandFailed {
			want = StepRspamdCheck
		}
		r := h.Apply(s)
		if r.OK || r.FailedStep != want || r.Rollback != antispam.RollbackVerified || strings.Contains(r.Error, key) {
			t.Fatalf("commandFailed=%t: result %+v", commandFailed, r)
		}
	}
}

// f0Key is the key newFake's KeyFacts carry.
func f0Key() string { return "abcdefghijklmnopqrstu23456" }

func TestSecureSecretPlansGroupOnlyRepair(t *testing.T) {
	target := antispam.TargetFacts{
		Target:  antispam.Target{Path: antispam.FeedRBLPath, Kind: antispam.TargetRspamdOptional},
		File:    antispam.PathFacts{Path: antispam.FeedRBLPath, UID: 0, GID: 974, Mode: antispam.SecretFileMode},
		Content: antispam.ManagedHeader + "\n",
	}
	changes := secureSecret(nil, []antispam.TargetFacts{target}, 975)
	if len(changes) != 1 {
		t.Fatalf("group-only drift planned %d writes, want one", len(changes))
	}
	c := changes[0]
	if c.target.Path != target.Path || c.next.content != target.Content || !c.next.exists || !c.next.metadata ||
		c.next.uid != -1 || c.next.gid != 975 || c.next.perm != antispam.SecretFileMode {
		t.Fatalf("group-only repair = %+v", c.next)
	}
}

func TestApplyRepairsDQSExactMode(t *testing.T) {
	for _, extra := range []fs.FileMode{fs.ModeSetuid, fs.ModeSetgid, fs.ModeSticky} {
		t.Run(extra.String(), func(t *testing.T) {
			f := newFake(t)
			s := dqsApply(f)
			wantOK(t, f.host().Apply(s))
			p := f.root + antispam.FeedRBLPath
			if err := os.Chmod(p, antispam.SecretFileMode|extra); err != nil {
				t.Fatal(err)
			}
			f.reset()
			wantOK(t, f.host().Apply(s))
			st, err := readFile(p)
			if err != nil || st.perm != antispam.SecretFileMode || st.gid != os.Getgid() {
				t.Fatalf("metadata not repaired: %v %v gid %d", err, st.perm, st.gid)
			}
		})
	}
}

// A rollback can put the key back into override.d/rbl.conf. It must come
// back private even when someone loosened the file during the apply.
func TestRollbackKeepsDQSPrivate(t *testing.T) {
	for _, disable := range []bool{false, true} {
		t.Run(map[bool]string{false: "rotate key", true: "disable DQS"}[disable], func(t *testing.T) {
			f := newFake(t)
			s := dqsApply(f)
			wantOK(t, f.host().Apply(s))
			p := f.root + antispam.FeedRBLPath
			prior := f.file(antispam.FeedRBLPath)
			f.reset()
			if disable {
				s.Feeds = []string{antispam.FeedPSBL}
				f.rbl = `{"rbls":{"csm_psbl":{}}}`
			} else {
				f.key.Key = antispam.NewSecret(otherKey)
			}
			f.fail["rspamadm configtest"] = []int{1}
			f.onCall = func(line string) {
				if line == "rspamadm configtest" {
					if err := os.Chmod(p, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			r := f.host().Apply(s)
			if r.OK || r.FailedStep != StepRspamdCheck || r.Rollback != antispam.RollbackVerified {
				t.Fatalf("result %+v", r)
			}
			st, err := readFile(p)
			if err != nil || st.content != prior || st.perm != antispam.SecretFileMode || st.gid != os.Getgid() {
				t.Fatalf("rollback restored the key file as %v gid %d (content restored %t)", st.perm, st.gid, st.content == prior)
			}
		})
	}
}
