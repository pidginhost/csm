package antispam

import "testing"

func TestRenderRspamdMatchesVerifiedFiles(t *testing.T) {
	files, err := RenderRspamd(defaults(false))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"actions.conf":     "# csm-managed-version: 1\nreject = 15;\nadd_header = 6;\ngreylist = null;\nrewrite_subject = null;\n",
		"greylist.conf":    "# csm-managed-version: 1\nenabled = false;\n",
		"rbl.conf":         "# csm-managed-version: 1\nenabled = false;\n",
		"emails.conf":      "# csm-managed-version: 1\nenabled = false;\n",
		"fuzzy_check.conf": "# csm-managed-version: 1\nenabled = false;\n",
		"asn.conf":         "# csm-managed-version: 1\nenabled = false;\n",
	}
	if len(files) != len(want) {
		t.Fatalf("rendered %d files, want %d: %v", len(files), len(want), files)
	}
	for name, content := range want {
		if files[name] != content {
			t.Errorf("%s = %q, want %q", name, files[name], content)
		}
	}
	for _, name := range RspamdFiles {
		if _, ok := files[name]; !ok {
			t.Errorf("RspamdFiles lists %s but it was not rendered", name)
		}
	}
}

func TestRenderRspamdThresholdsFollowSettings(t *testing.T) {
	s := defaults(true)
	s.RejectScore, s.TagScore = 20, 8
	files, err := RenderRspamd(s)
	if err != nil {
		t.Fatal(err)
	}
	want := "# csm-managed-version: 1\nreject = 20;\nadd_header = 8;\ngreylist = null;\nrewrite_subject = null;\n"
	if files["actions.conf"] != want {
		t.Errorf("actions.conf = %q, want %q", files["actions.conf"], want)
	}
}

func TestIsManaged(t *testing.T) {
	for content, want := range map[string]bool{
		"# csm-managed-version: 1\nenabled = false;\n": true,
		"# csm-managed-version: 1":                     true,
		"# csm-managed-version: 2\nenabled = false;\n": false,
		"enabled = false;\n# csm-managed-version: 1\n": false,
		" # csm-managed-version: 1\n":                  false,
		"":                                             false,
	} {
		if got := IsManaged(content); got != want {
			t.Errorf("IsManaged(%q) = %v, want %v", content, got, want)
		}
	}
}
