package antispam

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
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
		case TargetRspamd, TargetRspamdOptional:
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
		"/etc/rspamd/local.d/actions.conf":           TargetRspamd,
		"/etc/rspamd/local.d/greylist.conf":          TargetRspamd,
		"/etc/rspamd/local.d/rbl.conf":               TargetRspamd,
		"/etc/rspamd/local.d/emails.conf":            TargetRspamd,
		"/etc/rspamd/local.d/fuzzy_check.conf":       TargetRspamd,
		"/etc/rspamd/local.d/asn.conf":               TargetRspamd,
		"/etc/rspamd/local.d/phishing.conf":          TargetRspamd,
		"/etc/rspamd/override.d/rbl.conf":            TargetRspamdOptional,
		"/etc/rspamd/override.d/rbl_group.conf":      TargetRspamdOptional,
		"/etc/rspamd/local.d/forged_recipients.conf": TargetRspamdOptional,
		"/etc/rspamd/local.d/mid.conf":               TargetRspamdOptional,
		"/etc/rspamd/local.d/mime_types.conf":        TargetRspamdOptional,
		"/etc/rspamd/local.d/whitelist.conf":         TargetRspamdOptional,
		"/etc/rspamd/local.d/multimap.conf":          TargetRspamdOptional,
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
		delete(want, tg.Path)
	}
	if len(want) != 0 {
		t.Errorf("missing targets: %v", want)
	}
	if got[0].Kind != TargetRspamd || got[len(got)-1].Kind != TargetEximLocal {
		t.Errorf("rspamd files must come first and exim.conf.local last: %+v", got)
	}
}

func TestCheckHostAcceptsExistingCSMFiles(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		hooks, err := RenderExim(defaults(dryRun))
		if err != nil {
			t.Fatal(err)
		}
		contents := map[string]string{
			HookRCPTPath: hooks.RCPT,
			HookScanPath: hooks.Scan,
			HookPostPath: hooks.Post,
		}
		f := goodFacts()
		for i := range f.Targets {
			tg := &f.Targets[i]
			tg.Missing = false
			tg.File = PathFacts{Path: tg.Path, Mode: 0o644}
			switch tg.Kind {
			case TargetRspamd:
				tg.Content = ManagedHeader + "\nenabled = false;\n"
			case TargetEximHook:
				tg.Content = contents[tg.Path]
			case TargetEximLocal:
				tg.Content = "@CONFIG@\n" + hooks.Config
				f.LocalConf = tg.Content
			}
		}
		if got := CheckHost(f); len(got) != 0 {
			t.Fatalf("existing CSM files (dry run %t) reported %+v", dryRun, got)
		}
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

func TestCheckHostRejectsUncheckedTargetParents(t *testing.T) {
	for _, kind := range []TargetKind{TargetRspamd, TargetEximHook, TargetEximLocal} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("kind=%d/missing=%t", kind, missing), func(t *testing.T) {
				f := goodFacts()
				tg := target(&f, kind)
				tg.Parents = nil
				tg.Missing = missing
				tg.File = PathFacts{Path: tg.Path, Mode: 0o644}
				if kind == TargetRspamd {
					tg.Content = ManagedHeader + "\nenabled = false;\n"
				}
				got := CheckHost(f)
				if len(got) != 1 || got[0].Code != CodeTargets || got[0].Severity != Temporary {
					t.Fatalf("unchecked parents reported %+v, want one temporary target problem", got)
				}
			})
		}
	}
}

func TestCheckHostRetainsUnsafeTargetsAfterReadError(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*TargetFacts)
		detail string
	}{
		{"parent writable", func(tg *TargetFacts) {
			tg.Parents[len(tg.Parents)-1].Mode = fs.ModeDir | 0o777
		}, "writable by group or others"},
		{"parent owned by tenant", func(tg *TargetFacts) {
			tg.Parents[len(tg.Parents)-1].UID = 1001
		}, "owned by uid 1001"},
		{"file writable", func(tg *TargetFacts) { tg.File.Mode = 0o666 }, "writable by group or others"},
		{"file owned by tenant", func(tg *TargetFacts) { tg.File.UID = 1001 }, "owned by uid 1001"},
		{"file ACL", func(tg *TargetFacts) { tg.File.ExtACL = true }, "extra ACL entries"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts()
			tg := target(&f, TargetEximHook)
			tg.Err = fs.ErrPermission
			tc.mutate(tg)
			got := CheckHost(f)
			if len(got) != 1 || got[0].Code != CodeTargets || got[0].Severity != Definite || !strings.Contains(got[0].Detail, tc.detail) {
				t.Fatalf("known unsafe target reported %+v, want one definite problem containing %q", got, tc.detail)
			}
		})
	}
}

func TestCheckHostUnknownTargetMetadataStaysTemporary(t *testing.T) {
	for _, err := range []error{nil, fs.ErrPermission} {
		f := goodFacts()
		tg := target(&f, TargetEximHook)
		tg.File = PathFacts{}
		tg.Err = err
		got := CheckHost(f)
		if len(got) != 1 || got[0].Code != CodeTargets || got[0].Severity != Temporary {
			t.Fatalf("unknown stat (err %v) reported %+v, want one temporary target problem", err, got)
		}
	}
}

func TestCheckHostRejectsHookBlockContinuations(t *testing.T) {
	block := MarkerBegin + "\nwarn\n  logwrite = x\n" + MarkerEnd + "\n"
	for _, content := range []string{
		block + "  condition = false\n",
		block + "# operator comment\n\n  condition = false\n",
		block + ".ifdef X\n  condition = false\n.endif\n",
		"EXTRA = condition = false\n" + block + "EXTRA\n",
	} {
		f := goodFacts()
		target(&f, TargetEximHook).Content = content
		got := CheckHost(f)
		if len(got) != 1 || got[0].Code != CodeMarkers || got[0].Severity != Definite {
			t.Errorf("hook block continuation %q reported %+v, want one definite marker problem", content, got)
		}
	}
}

func TestCheckHostAcceptsIndependentHookStatements(t *testing.T) {
	block := MarkerBegin + "\nwarn\n  logwrite = x\n" + MarkerEnd + "\n"
	for _, suffix := range []string{
		"warn\n  condition = false\n",
		"# operator comment\n\nwarn\n  condition = false\n",
		".ifdef X\nwarn\n  condition = false\n.endif\n",
	} {
		f := goodFacts()
		target(&f, TargetEximHook).Content = block + suffix
		if got := CheckHost(f); len(got) != 0 {
			t.Errorf("independent hook statement %q reported %+v", suffix, got)
		}
	}
}

func TestCheckRemovalLeavesForeignFiles(t *testing.T) {
	targets := goodTargets()
	targets[0].Missing = false
	targets[0].File = PathFacts{Path: targets[0].Path, Mode: 0o644}
	targets[0].Content = "reject = 15;\n"
	targets[1].Err = fs.ErrNotExist
	for _, content := range []string{
		"@AUTH@\n",
		"@AUTH@\n" + MarkerBegin + "\nspamd_address = /run/rspamd/normal.sock\n" + MarkerEnd + "\n",
	} {
		targets[len(targets)-1].Content = content
		if got := CheckRemoval(targets); len(got) != 0 {
			t.Errorf("removal refused: %+v", got)
		}
	}
	if got := checkTargets(targets, false); len(got) != 3 {
		t.Errorf("apply problems = %+v, want foreign file, missing directory and @CONFIG@", got)
	}
}

func TestCheckRemovalRefusesUnsafeEdits(t *testing.T) {
	// The three ACL hook files follow the rspamd files.
	hook := len(MutationTargets()) - 4
	for name, edit := range map[string]func([]TargetFacts){
		"symlinked parent": func(ts []TargetFacts) { ts[6].Parents[2].Mode = fs.ModeSymlink | 0o777 },
		"tenant file":      func(ts []TargetFacts) { ts[hook].File.UID = 1000 },
		"unpaired marker":  func(ts []TargetFacts) { ts[hook+1].Content = MarkerBegin + "\n" },
	} {
		targets := goodTargets()
		edit(targets)
		if got := CheckRemoval(targets); len(got) == 0 || got[0].Severity != Definite {
			t.Errorf("%s: removal problems = %+v", name, got)
		}
	}
}

func TestCheckRemovalRefusesAmbiguousLocalBlocks(t *testing.T) {
	block := MarkerBegin + "\nspamd_address = /run/rspamd/normal.sock\n" + MarkerEnd + "\n"
	for name, tc := range map[string]struct {
		content string
		code    string
		sev     Severity
	}{
		"unpaired begin": {"@CONFIG@\n" + MarkerBegin + "\n", CodeMarkers, Definite},
		"unpaired end":   {"@CONFIG@\n" + MarkerEnd + "\n", CodeMarkers, Definite},
		"nested":         {"@CONFIG@\n" + MarkerBegin + "\n" + block + MarkerEnd + "\n", CodeMarkers, Definite},
		"duplicate":      {"@CONFIG@\n" + block + block, CodeMarkers, Definite},
		"include":        {"@CONFIG@\n.include /etc/exim_extra\n", CodeUnverifiable, Temporary},
		"section crossing": {"@CONFIG@\n" + MarkerBegin + "\n@ROUTERSTART@\n" +
			"# operator configuration\n" + MarkerEnd + "\n", CodeMarkers, Definite},
	} {
		t.Run(name, func(t *testing.T) {
			f := goodFacts()
			target(&f, TargetEximLocal).Content = tc.content
			got := CheckRemoval(f.Targets)
			if len(got) != 1 || got[0].Code != tc.code || got[0].Severity != tc.sev {
				t.Fatalf("removal reported %+v, want one %s/%d problem", got, tc.code, tc.sev)
			}
		})
	}
}

// Forward guard treats a whitespace-only exim.conf.local as absent and
// writes cPanel's skeleton; antispam does the same.
func TestCheckHostAcceptsBlankLocalConfig(t *testing.T) {
	for _, content := range []string{"", "\n", " \n\t\n"} {
		f := goodFacts()
		target(&f, TargetEximLocal).Content = content
		f.LocalConf = content
		if got := CheckHost(f); len(got) != 0 {
			t.Errorf("exim.conf.local %q reported %+v", content, got)
		}
	}
}

// Six rspamd files share local.d; a missing directory is one problem.
func TestCheckHostReportsMissingDirectoryOnce(t *testing.T) {
	f := goodFacts()
	for i := range f.Targets {
		if f.Targets[i].Kind == TargetRspamd {
			f.Targets[i].Err = fmt.Errorf("%s: %w", RspamdLocalDir, fs.ErrNotExist)
		}
	}
	got := CheckHost(f)
	if len(got) != 1 || got[0].Code != CodeTargets || got[0].Severity != Definite ||
		got[0].Detail != "the directory "+RspamdLocalDir+" is missing" {
		t.Fatalf("got %+v, want one missing-directory problem", got)
	}
}

func TestMutationTargetsListOptionalFiles(t *testing.T) {
	var optional []string
	for _, tgt := range MutationTargets() {
		if tgt.Kind == TargetRspamdOptional {
			optional = append(optional, tgt.Path)
		}
	}
	if !slices.Equal(optional, OptionalRspamdPaths()) {
		t.Fatalf("optional targets = %v", optional)
	}
}

func protectedParents() []PathFacts {
	return []PathFacts{{Path: "/", Mode: fs.ModeDir | 0o755}, {Path: "/etc", Mode: fs.ModeDir | 0o755}}
}

func TestCheckTargetsIgnoresForeignOptionalFiles(t *testing.T) {
	targets := goodTargets()
	for i := range targets {
		if targets[i].Kind == TargetRspamdOptional {
			targets[i].Missing = false
			targets[i].File = PathFacts{Path: targets[i].Path, Mode: 0o644}
			targets[i].Content = "operator text\n"
		}
	}
	if problems := checkTargets(targets, false); len(problems) != 0 {
		t.Fatalf("foreign optional files blocked core: %+v", problems)
	}
	if problems := checkTargets(targets, true); len(problems) != 0 {
		t.Fatalf("removal must leave foreign optional files alone: %+v", problems)
	}
}

func TestOptionalUsable(t *testing.T) {
	ok := TargetFacts{Target: Target{Path: FeedRBLPath, Kind: TargetRspamdOptional}, Missing: true, Parents: protectedParents()}
	if err := OptionalUsable(ok); err != nil {
		t.Fatalf("missing file in a safe directory: %v", err)
	}
	for name, mutate := range map[string]func(*TargetFacts){
		"missing dir":   func(f *TargetFacts) { f.Err = fmt.Errorf("lstat: %w", fs.ErrNotExist) },
		"unsafe parent": func(f *TargetFacts) { f.Parents[1].Mode = fs.ModeDir | 0o777 },
		"foreign": func(f *TargetFacts) {
			f.Missing, f.File, f.Content = false, PathFacts{Path: f.Path, Mode: 0o644}, "x\n"
		},
		"symlink": func(f *TargetFacts) { f.Missing, f.File = false, PathFacts{Path: f.Path, Mode: fs.ModeSymlink | 0o777} },
		"group writable": func(f *TargetFacts) {
			f.Missing, f.File, f.Content = false, PathFacts{Path: f.Path, Mode: 0o664}, ManagedHeader+"\n"
		},
	} {
		f := ok
		f.Parents = protectedParents()
		mutate(&f)
		if err := OptionalUsable(f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckTargetsJudgesUnsafeOptionalFilesOnlyForRemoval(t *testing.T) {
	targets := goodTargets()
	for i := range targets {
		if targets[i].Kind == TargetRspamdOptional {
			targets[i].Missing = false
			targets[i].File = PathFacts{Path: targets[i].Path, Mode: 0o666}
			targets[i].Content = ManagedHeader + "\n"
		}
	}
	if problems := checkTargets(targets, false); len(problems) != 0 {
		t.Fatalf("an unsafe optional file blocked core: %+v", problems)
	}
	if problems := checkTargets(targets, true); len(problems) == 0 || problems[0].Severity != Definite {
		t.Fatalf("removal must refuse to edit an unsafe CSM file: %+v", problems)
	}
}
