package txn

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/ipmap"
)

func TestApplyRechecksIPMapPreconditions(t *testing.T) {
	for name, mutate := range map[string]func(*antispam.HostFacts){
		"healthy": func(*antispam.HostFacts) {},
		"old version": func(f *antispam.HostFacts) {
			f.RspamdVersion.Stdout = "Rspamd daemon version 3.8.4\n"
		},
		"unknown version":        func(f *antispam.HostFacts) { f.RspamdVersion.Err = errors.New("unavailable") },
		"missing map":            func(f *antispam.HostFacts) { f.IPMap.Missing = true },
		"unreadable map":         func(f *antispam.HostFacts) { f.IPMap.File.Mode = 0o600 },
		"writable map":           func(f *antispam.HostFacts) { f.IPMap.File.Mode = 0o660 },
		"unknown group":          func(f *antispam.HostFacts) { f.RspamdGID = -1 },
		"inaccessible directory": func(f *antispam.HostFacts) { f.IPMap.Parents[0].Mode = fs.ModeDir | 0o700 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.multimap = loadedIPMapRule
			s := enforce()
			s.Feeds = []string{antispam.FeedCSMIPMap, antispam.FeedRspamdMaps}
			h := f.host()
			preflight := h.preflight
			h.preflight = func(ctx context.Context, s antispam.Settings) (antispam.HostFacts, []antispam.Problem) {
				facts, problems := preflight(ctx, s)
				facts.IPMap = antispam.FileFacts{File: antispam.PathFacts{Path: ipmap.DefaultPath, Mode: 0o640, GID: facts.RspamdGID}}
				facts.IPMap.Parents = []antispam.PathFacts{{Path: "/", Mode: fs.ModeDir | 0o755}}
				mutate(&facts)
				return facts, problems
			}
			before := f.state()
			r := h.Apply(s)
			if name == "healthy" {
				wantOK(t, r)
				if f.count("systemctl reload rspamd.service") != 1 {
					t.Fatal("healthy IP map was not applied")
				}
				return
			}
			if r.OK || r.FailedStep != StepPreconditions || r.Rollback != antispam.RollbackNone {
				t.Fatalf("invalid IP map request was not rejected before mutation: %+v", r)
			}
			if len(f.calls) != 0 || !maps.Equal(before, f.state()) {
				t.Fatal("invalid IP map request ran commands or changed files")
			}
		})
	}
}
