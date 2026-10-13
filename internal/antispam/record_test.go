package antispam

import (
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

func TestManagedContentCoversEveryTarget(t *testing.T) {
	s := enforceSettings()
	content, err := ManagedContent(s)
	if err != nil {
		t.Fatal(err)
	}
	targets := MutationTargets()
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
	for _, target := range MutationTargets() {
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
	targets := installedTargets(t, enforceSettings())
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
