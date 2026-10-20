package txn

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

const otherKey = "zyxwvutsrqponmlkjihgf65432"

func TestApplyRechecksDQSLogPrivacy(t *testing.T) {
	f := newFake(t)
	s := dqsApply(f)
	h := f.host()
	preflight := h.preflight
	h.preflight = func(ctx context.Context, s antispam.Settings) (antispam.HostFacts, []antispam.Problem) {
		facts, problems := preflight(ctx, s)
		facts.RspamdLog = antispam.LogFacts{Type: "file", Path: "/var/log/rspamd/rspamd.log",
			File:    antispam.PathFacts{Mode: 0o644},
			Parents: []antispam.PathFacts{{Path: "/", Mode: fs.ModeDir | 0o755}}}
		return facts, problems
	}
	before := f.state()
	r := h.Apply(s)
	if r.OK || r.FailedStep != StepPreconditions || r.Rollback != antispam.RollbackNone {
		t.Fatalf("exposed log was not rejected before mutation: %+v", r)
	}
	if len(f.calls) != 0 || !maps.Equal(before, f.state()) {
		t.Fatal("exposed log request ran commands or changed files")
	}
}

func TestApplyRechecksFeedVersion(t *testing.T) {
	for _, feeds := range [][]string{nil, {antispam.FeedPSBL, antispam.FeedRspamdMaps}, {antispam.FeedRspamdMaps}} {
		f := newFake(t)
		f.modules, f.rbl = "Modules enabled: dkim, spf, rbl\n", `{"rbls":{"csm_psbl":{}}}`
		s := enforce()
		s.Feeds = feeds
		if len(s.DNSFeeds()) == 0 {
			f.modules, f.rbl = "", ""
		}
		h := f.host()
		preflight := h.preflight
		h.preflight = func(ctx context.Context, s antispam.Settings) (antispam.HostFacts, []antispam.Problem) {
			facts, problems := preflight(ctx, s)
			facts.RspamdVersion.Stdout = "Rspamd daemon version 3.8.4\n"
			return facts, problems
		}
		before := f.state()
		r := h.Apply(s)
		if len(s.DNSFeeds()) == 0 && !s.Redirects() {
			wantOK(t, r)
		} else if r.OK || r.FailedStep != StepPreconditions || len(f.calls) != 0 || !maps.Equal(before, f.state()) {
			t.Fatal("unsupported feed or map request changed the host")
		}
	}
}

func TestDQSFeedTogglesLeaveEximAlone(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	for _, on := range []bool{true, false, true} {
		f.reset()
		s := enforce()
		if on {
			s = dqsApply(f)
		} else {
			f.modules, f.rbl = "", ""
		}
		wantOK(t, f.host().Apply(s))
		if f.count(BuildEximConf) != 0 || f.count("systemctl reload exim.service") != 0 ||
			f.count("systemctl reload rspamd.service") != 1 {
			t.Fatalf("on=%t: feed toggle did not reload only rspamd", on)
		}
	}
}

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
		r := h.Apply(s)
		if r.OK || r.FailedStep != StepFeedsCheck || r.Rollback != antispam.RollbackVerified || strings.Contains(r.Error, key) {
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
	changes := secureSecret(nil, []antispam.TargetFacts{target}, 975, []string{antispam.FeedRBLPath})
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

func TestSecretMetadataDriftPlansOnlyRBLReplacement(t *testing.T) {
	const serviceGID = 974
	for _, tc := range []struct {
		name string
		gid  int
		mode fs.FileMode
	}{
		{"group", 979, antispam.SecretFileMode},
		{"mode", serviceGID, 0o644},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.modules = "Modules enabled: dkim, spf, rbl\n"
			f.rbl = `{"rbls":{"csm_dqs_zen":{},"csm_dqs_dbl":{},"csm_dqs_zrd":{}}}`
			s := enforce()
			s.Feeds = []string{antispam.FeedSpamhausDQS}
			s.DQSKeyFile, s.DQSKey = f.key.Path, f.key.Key
			managed, err := antispam.ManagedContent(s)
			if err != nil {
				t.Fatal("cannot render DQS configuration")
			}
			if result := f.host().Apply(s); !result.OK {
				t.Fatal("cannot install DQS configuration")
			}
			targets := f.host().targets()
			for i := range targets {
				target := &targets[i]
				if target.Path == antispam.FeedRBLPath {
					target.File.GID, target.File.Mode = tc.gid, tc.mode
				}
			}
			changes, err := plan(targets, managed)
			if err != nil || len(changes) != 0 {
				t.Fatal("unchanged content produced edits or failed planning")
			}
			changes = secureSecret(changes, targets, serviceGID, []string{antispam.FeedRBLPath})
			if len(changes) != 1 || changes[0].target.Path != antispam.FeedRBLPath {
				t.Fatal("metadata drift must replace only the DQS configuration")
			}
			next := changes[0].next
			if !next.exists || !next.metadata || next.uid != -1 || next.gid != serviceGID || next.perm != antispam.SecretFileMode {
				t.Fatal("replacement must retain worker ownership and restrict access to the service group")
			}
			if next.content != managed[antispam.FeedRBLPath] {
				t.Fatal("metadata repair changed the DQS configuration content")
			}
		})
	}
}

// A loosened override.d/rbl.conf can hold the key; CSM still owns it and
// deletes it, on apply once the daemon drops the feeds and on removal.
func TestLoosenedKeyFileIsDeleted(t *testing.T) {
	for _, mode := range []os.FileMode{0o664, 0o666} {
		for _, remove := range []bool{false, true} {
			f := newFake(t)
			s := dqsApply(f)
			wantOK(t, f.host().Apply(s))
			p := f.root + antispam.FeedRBLPath
			if err := os.Chmod(p, mode); err != nil {
				t.Fatal(err)
			}
			f.reset()
			f.modules, f.rbl = "", ""
			if remove {
				wantOK(t, f.host().Remove())
			} else {
				wantOK(t, f.host().Apply(enforce()))
			}
			if got := f.file(antispam.FeedRBLPath); got != "<absent>" {
				t.Fatalf("mode %v remove=%t: key file left behind", mode, remove)
			}
		}
	}
}
