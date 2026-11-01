package antispam

import (
	"maps"
	"path"
	"strings"
	"testing"
)

func TestRecordRoundTrip(t *testing.T) {
	for _, gen := range []string{"", strings.Repeat("ab", 32)} {
		r, err := DecodeRecord(EncodeRecord(gen))
		if err != nil {
			t.Fatalf("generation %q: %v", gen, err)
		}
		if r.Complete() != (gen != "") || r.Complete() && *r.Generation != gen {
			t.Errorf("generation %q: decoded %+v", gen, r)
		}
	}
	if got := string(EncodeRecord("")); got != `{"format":1,"generation":null}`+"\n" {
		t.Errorf("incomplete record = %q", got)
	}
}

func TestDecodeRecordRejects(t *testing.T) {
	digest := strings.Repeat("0", 64)
	for name, data := range map[string]string{
		"empty":             ``,
		"array":             `[]`,
		"missing format":    `{"generation":null}`,
		"missing gen":       `{"format":1}`,
		"format 2":          `{"format":2,"generation":null}`,
		"format float":      `{"format":1.0,"generation":null}`,
		"format string":     `{"format":"1","generation":null}`,
		"short digest":      `{"format":1,"generation":"abc"}`,
		"uppercase digest":  `{"format":1,"generation":"` + strings.ToUpper(strings.Repeat("ab", 32)) + `"}`,
		"numeric gen":       `{"format":1,"generation":5}`,
		"unknown field":     `{"format":1,"generation":null,"x":1}`,
		"duplicate field":   `{"format":1,"format":1,"generation":null}`,
		"case variant":      `{"Format":1,"generation":null}`,
		"trailing data":     `{"format":1,"generation":"` + digest + `"}{}`,
		"oversized":         `{"format":1,"generation":null}` + strings.Repeat(" ", MaxRecordBytes),
		"nested generation": `{"format":1,"generation":{}}`,
	} {
		if r, err := DecodeRecord([]byte(data)); err == nil {
			t.Errorf("%s: accepted as %+v", name, r)
		}
	}
}

func TestGenerationIsCanonical(t *testing.T) {
	a := map[string]string{"/b": "x<y>&z\n", "/a": "1"}
	b := map[string]string{"/a": "1", "/b": "x<y>&z\n"}
	if Generation(a) != Generation(b) {
		t.Error("generation depends on map order")
	}
	// Pinned: sha256 of {"/a":"1","/b":"x<y>&z\n"} with no HTML escaping.
	if got, want := Generation(a), "de474220270189e95ed0ebea620238f32b00e06ae3b10533e4fa65cce5d8bff3"; got != want {
		t.Errorf("Generation = %s, want %s", got, want)
	}
	c := map[string]string{"/a": "1", "/b": "x<y>&z"}
	if Generation(a) == Generation(c) {
		t.Error("generation ignores content")
	}
}

// everyOptional wants every optional file: a DNS feed, learning and the
// Roundcube include.
func everyOptional() Settings {
	s := enforceSettings()
	s.Feeds = []string{FeedPSBL}
	s.Learning, s.LearningDir, s.Roundcube = true, DefaultLearningDir, true
	s.LearningKeys = syntheticLearningKeys()
	return s
}

func TestManagedContentCoversEveryTarget(t *testing.T) {
	s := everyOptional()
	content, err := ManagedContent(s)
	if err != nil {
		t.Fatal(err)
	}
	targets := MutationTargets(StackExim)
	if len(content) != len(targets) {
		t.Fatalf("%d managed texts for %d targets", len(content), len(targets))
	}
	for _, target := range targets {
		if content[target.Path] == "" {
			t.Errorf("no managed text for %s", target.Path)
		}
	}
	dry := s
	dry.DryRun = true
	other, _ := ManagedContent(dry)
	if Generation(content) == Generation(other) {
		t.Error("dry_run does not change the generation")
	}
	if _, err := ManagedContent(Settings{}); err == nil {
		t.Error("invalid settings accepted")
	}
}

// installedTargets is what the collector reports once content is on disk.
func installedTargets(t *testing.T, s Settings) []TargetFacts {
	t.Helper()
	content, err := ManagedContent(s)
	if err != nil {
		t.Fatal(err)
	}
	var out []TargetFacts
	for _, target := range MutationTargets(StackExim) {
		text := content[target.Path]
		switch target.Kind {
		case TargetEximHook:
			text += "warn\n  log_message = operator rule\n"
		case TargetEximLocal:
			text = "@CONFIG@\n" + text + "\n@ROUTERSTART@\n"
		}
		out = append(out, TargetFacts{Target: target, Content: text})
	}
	return out
}

func TestInstalledContentMatchesManagedContent(t *testing.T) {
	for _, dry := range []bool{false, true} {
		s := enforceSettings()
		s.DryRun = dry
		want, err := ManagedContent(s)
		if err != nil {
			t.Fatal(err)
		}
		targets := installedTargets(t, s)
		for i := range targets {
			if targets[i].Kind == TargetEximLocal {
				targets[i].Content = "@AUTH@\n.ifdef OPTIONAL_SETTING\n# operator content\n.endif\n" + targets[i].Content
			}
		}
		if got := InstalledContent(targets); Generation(got) != Generation(want) {
			t.Errorf("dry run %t: installed content %v differs from managed content", dry, got)
		}
	}
}

func TestInstalledContentSkipsForeignAndMissing(t *testing.T) {
	s := everyOptional()
	targets := installedTargets(t, s)
	targets[0].Content = "reject = 15;\n"
	targets[1].Missing = true
	targets[6].Content = "warn\n  log_message = operator rule\n"
	got := InstalledContent(targets)
	for _, i := range []int{0, 1, 6} {
		if _, ok := got[targets[i].Path]; ok {
			t.Errorf("%s reported as installed", targets[i].Path)
		}
	}
	if len(got) != len(targets)-3 {
		t.Errorf("installed %d targets, want %d", len(got), len(targets)-3)
	}
}

func TestInstalledContentRejectsInactiveOrDisplacedBlocks(t *testing.T) {
	s := enforceSettings()
	s.Socket = "/run/rspamd/CSM_SOCKET.sock"
	want, err := ManagedContent(s)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		path    string
		content string
	}{
		"RCPT bypass": {HookRCPTPath, "accept\n" + want[HookRCPTPath]},
		"scan bypass": {HookScanPath, "accept\n" + want[HookScanPath]},
		"post bypass": {HookPostPath, "accept\n" + want[HookPostPath]},
		"wrong local section": {
			LocalEximConfPath, "@CONFIG@\n@AUTH@\n" + want[LocalEximConfPath],
		},
		"conditional hook": {
			HookRCPTPath, ".ifdef CSM_DISABLED_HOOK\n" + want[HookRCPTPath] + ".endif\n",
		},
		"conditional local section": {
			LocalEximConfPath, ".ifdef CSM_DISABLED_HOOK\n@CONFIG@\n" + want[LocalEximConfPath] + ".endif\n",
		},
		"macro changes scanner": {
			LocalEximConfPath, "CSM_SOCKET = other\n@CONFIG@\n" + want[LocalEximConfPath],
		},
	} {
		t.Run(name, func(t *testing.T) {
			targets := installedTargets(t, s)
			for i := range targets {
				if targets[i].Path == tc.path {
					targets[i].Content = tc.content
				}
			}
			got := InstalledContent(targets)
			if _, ok := got[tc.path]; ok {
				t.Error("inactive or displaced block reported as installed")
			}
			if len(got) != len(want)-1 {
				t.Errorf("installed %d targets, want %d", len(got), len(want)-1)
			}
			if Generation(got) == Generation(want) {
				t.Error("inactive or displaced block matches the completed generation")
			}
		})
	}
}

func TestManagedContentIncludesFeedFiles(t *testing.T) {
	s := defaults(false)
	s.Feeds = []string{FeedPSBL}
	managed, err := ManagedContent(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{FeedRBLPath, FeedRBLGroupPath, RedirectPath(RedirectMultimap)} {
		if _, ok := managed[p]; !ok {
			t.Errorf("ManagedContent lacks %s", p)
		}
	}
}

func TestManagedContentSetsSymbolWeights(t *testing.T) {
	if ScoresPath != "/etc/rspamd/local.d/groups.conf" {
		t.Fatalf("ScoresPath = %s, want rspamd's local groups include", ScoresPath)
	}
	managed, err := ManagedContent(defaults(false))
	if err != nil {
		t.Fatal(err)
	}
	want := "# csm-managed-version: 1\ngroup \"html\" {\n  symbols {\n    \"HIDDEN_TEXT\" {\n" +
		"      weight = 2.0;\n      one_shot = true;\n    }\n  }\n}\n" +
		"group \"url\" {\n  symbols {\n    \"URL_VERY_LONG\" {\n" +
		"      weight = 1.5;\n      one_shot = true;\n    }\n  }\n}\n"
	if managed[ScoresPath] != want {
		t.Fatalf("%s =\n%q\nwant\n%q", ScoresPath, managed[ScoresPath], want)
	}
	s := defaults(false)
	s.SkipScores = true
	if managed, err = ManagedContent(s); err != nil {
		t.Fatal(err)
	}
	if _, ok := managed[ScoresPath]; ok {
		t.Fatalf("skipped %s rendered", ScoresPath)
	}
}

// On Postfix CSM owns the rspamd files, the milter headers and the scope
// Lua, never an Exim file or the Roundcube include. In dry run the host's
// own actions.conf keeps enforcing, so CSM leaves that file out.
func TestManagedContentPostfixDryRunOmitsActions(t *testing.T) {
	s := everyOptional()
	s.Stack = StackPostfix
	actions := path.Join(RspamdLocalDir, "actions.conf")
	postfix, err := RenderPostfix(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, dry := range []bool{false, true} {
		s.DryRun = dry
		content, err := ManagedContent(s)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{}
		for _, target := range MutationTargets(StackPostfix) {
			want[target.Path] = true
		}
		if dry {
			delete(want, actions)
		}
		if len(content) != len(want) {
			t.Errorf("dry run %t: %d managed texts for %d targets", dry, len(content), len(want))
		}
		for p, text := range content {
			if !want[p] || text == "" {
				t.Errorf("dry run %t: unexpected managed text for %s", dry, p)
			}
		}
		for p, text := range postfix {
			if content[p] != text {
				t.Errorf("dry run %t: %s = %q, want %q", dry, p, content[p], text)
			}
		}
	}
}

// The daemon now names the stack on cPanel hosts; the content and its
// generation must stay what an unnamed stack produced.
func TestManagedContentEximStackUnchanged(t *testing.T) {
	for _, s := range []Settings{defaults(false), defaults(true), everyOptional()} {
		unset, err := ManagedContent(s)
		if err != nil {
			t.Fatal(err)
		}
		s.Stack = StackExim
		exim, err := ManagedContent(s)
		if err != nil {
			t.Fatal(err)
		}
		if !maps.Equal(unset, exim) {
			t.Errorf("StackExim changed the managed content for %+v", s)
		}
	}
}
