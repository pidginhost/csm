package antispam

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"testing"
)

// rootChain is a protected directory chain from "/" down to dir.
func rootChain(dir string) []PathFacts {
	out := []PathFacts{{Path: "/", Mode: fs.ModeDir | 0o755}}
	p := ""
	for _, name := range strings.Split(strings.TrimPrefix(dir, "/"), "/") {
		p += "/" + name
		out = append(out, PathFacts{Path: p, Mode: fs.ModeDir | 0o755})
	}
	return out
}

// goodTargets is a fresh host: no rspamd files yet, cPanel's empty hook
// files and an exim.conf.local with the cPanel section skeleton.
func goodTargets() []TargetFacts {
	var out []TargetFacts
	for _, t := range MutationTargets() {
		f := TargetFacts{Target: t, Parents: rootChain(path.Dir(t.Path))}
		switch t.Kind {
		case TargetRspamd:
			f.Missing = true
		case TargetEximHook:
			f.File = PathFacts{Path: t.Path, Mode: 0o644}
		case TargetEximLocal:
			f.File = PathFacts{Path: t.Path, Mode: 0o644}
			f.Content = "@AUTH@\n\n@CONFIG@\n\n@DIRECTOREND@\n"
		}
		out = append(out, f)
	}
	return out
}

// target returns the first target of kind k in f.
func target(f *HostFacts, k TargetKind) *TargetFacts {
	for i := range f.Targets {
		if f.Targets[i].Kind == k {
			return &f.Targets[i]
		}
	}
	panic(fmt.Sprintf("no target of kind %d", k))
}

func TestMutationTargetsCoverSpecFiles(t *testing.T) {
	want := map[string]TargetKind{
		"/etc/rspamd/local.d/actions.conf":     TargetRspamd,
		"/etc/rspamd/local.d/greylist.conf":    TargetRspamd,
		"/etc/rspamd/local.d/rbl.conf":         TargetRspamd,
		"/etc/rspamd/local.d/emails.conf":      TargetRspamd,
		"/etc/rspamd/local.d/fuzzy_check.conf": TargetRspamd,
		"/etc/rspamd/local.d/asn.conf":         TargetRspamd,
		"/usr/local/cpanel/etc/exim/acls/ACL_SPAM_SCAN_CHECK_BLOCK/custom_begin_spam_scan_check":       TargetEximHook,
		"/usr/local/cpanel/etc/exim/acls/ACL_SPAM_SCAN_BLOCK/custom_begin_spam_scan":                   TargetEximHook,
		"/usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_POST_BLOCK/custom_begin_check_message_post": TargetEximHook,
		"/etc/exim.conf.local": TargetEximLocal,
	}
	got := MutationTargets()
	if len(got) != len(want) {
		t.Fatalf("got %d targets, want %d: %+v", len(got), len(want), got)
	}
	for _, tg := range got {
		if kind, ok := want[tg.Path]; !ok || kind != tg.Kind {
			t.Errorf("unexpected target %+v", tg)
		}
	}
	if got[0].Kind != TargetRspamd || got[len(got)-1].Kind != TargetEximLocal {
		t.Errorf("rspamd files must come first and exim.conf.local last: %+v", got)
	}
}

func TestCheckHostAcceptsExistingCSMFiles(t *testing.T) {
	f := goodFacts()
	for i := range f.Targets {
		tg := &f.Targets[i]
		tg.Missing = false
		tg.File = PathFacts{Path: tg.Path, Mode: 0o644}
		switch tg.Kind {
		case TargetRspamd:
			tg.Content = ManagedHeader + "\nenabled = false;\n"
		case TargetEximHook:
			tg.Content = MarkerBegin + "\nwarn\n  logwrite = x\n" + MarkerEnd + "\n"
		case TargetEximLocal:
			tg.Content = "@CONFIG@\n" + MarkerBegin + "\nspamd_address = /run/rspamd/csm-normal.sock variant=rspamd tmo=30s\n" + MarkerEnd + "\n"
		}
	}
	if got := CheckHost(f); len(got) != 0 {
		t.Fatalf("existing CSM files reported %+v", got)
	}
}

func TestCheckHostAcceptsMissingLocalConfig(t *testing.T) {
	f := goodFacts()
	local := target(&f, TargetEximLocal)
	local.Missing, local.File, local.Content = true, PathFacts{}, ""
	f.LocalConf = ""
	if got := CheckHost(f); len(got) != 0 {
		t.Fatalf("absent exim.conf.local reported %+v", got)
	}
}

func TestCheckHostTargetProblems(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name   string
		mutate func(*HostFacts)
		code   string
		sev    Severity
	}{
		{"targets unchecked", func(f *HostFacts) { f.Targets = nil }, CodeTargets, Temporary},
		{"target unreadable", func(f *HostFacts) { target(f, TargetEximHook).Err = boom }, CodeTargets, Temporary},
		{"directory missing", func(f *HostFacts) {
			target(f, TargetRspamd).Err = fmt.Errorf("%s: %w", RspamdLocalDir, fs.ErrNotExist)
		}, CodeTargets, Definite},
		{"foreign rspamd file", func(f *HostFacts) {
			tg := target(f, TargetRspamd)
			tg.Missing, tg.File, tg.Content = false, PathFacts{Path: tg.Path, Mode: 0o644}, "reject = 15;\n"
		}, CodeTargets, Definite},
		{"newer managed version", func(f *HostFacts) {
			tg := target(f, TargetRspamd)
			tg.Missing, tg.File, tg.Content = false, PathFacts{Path: tg.Path, Mode: 0o644}, "# csm-managed-version: 2\n"
		}, CodeTargets, Definite},
		{"target is a symlink", func(f *HostFacts) { target(f, TargetEximHook).File.Mode = fs.ModeSymlink | 0o777 }, CodeTargets, Definite},
		{"target is a directory", func(f *HostFacts) { target(f, TargetEximHook).File.Mode = fs.ModeDir | 0o755 }, CodeTargets, Definite},
		{"target writable by others", func(f *HostFacts) { target(f, TargetEximHook).File.Mode = 0o666 }, CodeTargets, Definite},
		{"target owned by tenant", func(f *HostFacts) { target(f, TargetEximHook).File.UID = 1001 }, CodeTargets, Definite},
		{"target ACL", func(f *HostFacts) { target(f, TargetEximHook).File.ExtACL = true }, CodeTargets, Definite},
		{"parent symlink", func(f *HostFacts) {
			tg := target(f, TargetEximHook)
			tg.Parents[len(tg.Parents)-1].Mode = fs.ModeSymlink | 0o777
		}, CodeTargets, Definite},
		{"parent writable", func(f *HostFacts) {
			tg := target(f, TargetEximHook)
			tg.Parents[len(tg.Parents)-1].Mode = fs.ModeDir | 0o775
		}, CodeTargets, Definite},
		{"parent owned by tenant", func(f *HostFacts) {
			tg := target(f, TargetEximHook)
			tg.Parents[len(tg.Parents)-1].UID = 1001
		}, CodeTargets, Definite},
		{"parent ACL", func(f *HostFacts) {
			tg := target(f, TargetEximHook)
			tg.Parents[len(tg.Parents)-1].ExtACL = true
		}, CodeTargets, Definite},
		{"hook with two blocks", func(f *HostFacts) {
			block := MarkerBegin + "\nwarn\n" + MarkerEnd + "\n"
			target(f, TargetEximHook).Content = block + block
		}, CodeMarkers, Definite},
		{"hook with unpaired marker", func(f *HostFacts) { target(f, TargetEximHook).Content = MarkerBegin + "\n" }, CodeMarkers, Definite},
		{"hook include", func(f *HostFacts) { target(f, TargetEximHook).Content = ".include /etc/exim_extra\n" }, CodeUnverifiable, Temporary},
		{"local without CONFIG", func(f *HostFacts) { target(f, TargetEximLocal).Content = "@AUTH@\n" }, CodeTargets, Definite},
		{"local with two CONFIG", func(f *HostFacts) { target(f, TargetEximLocal).Content = "@CONFIG@\n@CONFIG@\n" }, CodeTargets, Definite},
		{"local with indented CONFIG", func(f *HostFacts) { target(f, TargetEximLocal).Content = "  @CONFIG@\n" }, CodeTargets, Definite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts()
			tc.mutate(&f)
			got := CheckHost(f)
			if len(got) != 1 {
				t.Fatalf("got %d problems %+v, want exactly one %s", len(got), got, tc.code)
			}
			if got[0].Code != tc.code || got[0].Severity != tc.sev {
				t.Errorf("got %s/%d (%s), want %s/%d", got[0].Code, got[0].Severity, got[0].Detail, tc.code, tc.sev)
			}
		})
	}
}

// Several targets share /etc; an unsafe shared directory is one problem.
func TestCheckHostReportsSharedParentOnce(t *testing.T) {
	f := goodFacts()
	for i := range f.Targets {
		for j := range f.Targets[i].Parents {
			if f.Targets[i].Parents[j].Path == "/etc" {
				f.Targets[i].Parents[j].Mode = fs.ModeDir | 0o777
			}
		}
	}
	got := CheckHost(f)
	if len(got) != 1 || got[0].Code != CodeTargets || !strings.HasPrefix(got[0].Detail, "/etc is writable") {
		t.Fatalf("got %+v, want one /etc problem", got)
	}
}

// A file under an unsafe directory is not judged on its own content: the
// directory is the problem the operator must fix first.
func TestCheckHostSkipsFilesUnderUnsafeDirectories(t *testing.T) {
	f := goodFacts()
	tg := target(&f, TargetEximLocal)
	tg.Parents[1].Mode = fs.ModeSymlink | 0o777
	tg.File, tg.Content = PathFacts{}, ""
	got := CheckHost(f)
	if len(got) != 1 || !strings.Contains(got[0].Detail, "is not a directory") {
		t.Fatalf("got %+v, want only the symlinked directory", got)
	}
}
