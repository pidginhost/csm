package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestDropperDocrootFor(t *testing.T) {
	docroots := []string{
		"/home/alice/public_html",
		"/home/alice/public_html/sub.example.com",
		"/home/bob/public_html",
	}
	cases := []struct {
		name string
		path string
		want string
	}{
		{"inside primary docroot", "/home/alice/public_html/wp-content/plugins/x/x.php", "/home/alice/public_html"},
		{"longest docroot wins for addon subdir", "/home/alice/public_html/sub.example.com/a.php", "/home/alice/public_html/sub.example.com"},
		{"outside any docroot", "/home/alice/mail/x.php", ""},
		{"sibling dir sharing docroot prefix", "/home/alice/public_html_old/x.php", ""},
		{"path equal to docroot is not under it", "/home/bob/public_html", ""},
		{"other account docroot", "/home/bob/public_html/index.php", "/home/bob/public_html"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dropperDocrootFor(tc.path, docroots); got != tc.want {
				t.Errorf("dropperDocrootFor(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func freshDropperCandidate(now time.Time) dropperCandidate {
	return dropperCandidate{
		Path:       "/home/alice/public_html/wp-content/plugins/media-opt/media-opt.php",
		Docroot:    "/home/alice/public_html",
		Observed:   now,
		Birth:      now.Add(-2 * time.Second),
		BirthKnown: true,
		Mode:       0o100644,
		Size:       1621,
		PID:        4242,
		Head:       []byte("<?php /* fake plugin loader */ if (isset($_GET['k'])) { system($_POST['c']); }"),
	}
}

func TestShouldTrackDropper(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	fresh := 5 * time.Minute
	const selfPID = 999

	cases := []struct {
		name   string
		mutate func(*dropperCandidate)
		want   bool
	}{
		{"fresh php file under docroot", func(c *dropperCandidate) {}, true},
		{"executable non-php file", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/assets/miner"
			c.Mode = 0o100755
			c.Head = []byte("\x7fELF\x02\x01\x01")
		}, true},
		{"outside docroot", func(c *dropperCandidate) { c.Docroot = "" }, false},
		{"directory event", func(c *dropperCandidate) { c.Mode = 0o040755 }, false},
		{"plain data file without php ext or exec bit", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/tmp/sess_a1b2c3d4"
			c.Head = []byte(`user|s:5:"admin";`)
		}, false},
		{"opcache binary blob", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/opcache/index.php.bin"
			c.Head = []byte("OPCACHE\x00")
		}, false},
		{"atomic-write staging name", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/.temp.1770000000123.plugin.php"
		}, false},
		{"stale file modified not created", func(c *dropperCandidate) {
			c.Birth = now.Add(-48 * time.Hour)
		}, false},
		{"birth time unavailable", func(c *dropperCandidate) { c.BirthKnown = false }, false},
		{"csm's own write", func(c *dropperCandidate) { c.PID = selfPID }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := freshDropperCandidate(now)
			tc.mutate(&c)
			if got := shouldTrackDropper(c, selfPID, fresh); got != tc.want {
				t.Errorf("shouldTrackDropper() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDropperTrackerObserveDue(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(3 * time.Minute)

	c := freshDropperCandidate(now)
	tr.Observe(c)

	if due := tr.Due(now.Add(1 * time.Minute)); len(due) != 0 {
		t.Fatalf("Due before TTL returned %d entries, want 0", len(due))
	}
	due := tr.Due(now.Add(3*time.Minute + time.Second))
	if len(due) != 1 || due[0].Path != c.Path {
		t.Fatalf("Due after TTL = %+v, want the observed candidate", due)
	}
	if again := tr.Due(now.Add(10 * time.Minute)); len(again) != 0 {
		t.Fatalf("Due must remove returned entries, got %d again", len(again))
	}
}

func TestDropperTrackerReobserveKeepsFirstSeen(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(3 * time.Minute)

	c := freshDropperCandidate(now)
	tr.Observe(c)
	c2 := c
	c2.Observed = now.Add(2 * time.Minute)
	c2.Size = 9000
	tr.Observe(c2)

	// TTL runs from the FIRST observation: repeated rewrites must not let a
	// file postpone its probe forever.
	due := tr.Due(now.Add(3*time.Minute + time.Second))
	if len(due) != 1 {
		t.Fatalf("got %d due entries, want 1", len(due))
	}
	if !due[0].Observed.Equal(now) {
		t.Errorf("Observed = %v, want first-seen %v", due[0].Observed, now)
	}
	if due[0].Size != 9000 {
		t.Errorf("Size = %d, want latest metadata 9000", due[0].Size)
	}
}

func TestWPUpgradeRenameCandidates(t *testing.T) {
	cases := []struct {
		name string
		path string
		want []string
	}{
		{
			"plugin upgrade staging",
			"/home/alice/public_html/wp-content/upgrade/hello-dolly-a1b2/hello-dolly/hello.php",
			[]string{
				"/home/alice/public_html/wp-content/plugins/hello-dolly/hello.php",
				"/home/alice/public_html/wp-content/themes/hello-dolly/hello.php",
			},
		},
		{
			"core upgrade staging",
			"/home/alice/public_html/wp-content/upgrade/wordpress-6.5/wordpress/wp-includes/version.php",
			[]string{
				"/home/alice/public_html/wp-includes/version.php",
			},
		},
		{
			"not under upgrade dir",
			"/home/alice/public_html/wp-content/plugins/x/x.php",
			nil,
		},
		{
			"upgrade file without package subdir",
			"/home/alice/public_html/wp-content/upgrade/loose.php",
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := wpUpgradeRenameCandidates(tc.path)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("candidate[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestLooksLikeCompiledTemplate(t *testing.T) {
	twig := []byte("<?php\n\nuse Twig\\Environment;\nuse Twig\\Template;\n\n/* tables/browse.twig */\nclass __TwigTemplate_9f8ab12cd34ef56 extends Template\n{")
	smarty := []byte("<?php\n/* Smarty version 4.3.1, created on 2026-07-19 17:27:12\n  from 'index.tpl' */\n")
	shell := []byte("<?php if (isset($_GET['k']) && hash_equals($t,$_GET['k'])) { system($_POST['c']); }")
	plain := []byte("<?php\nrequire __DIR__ . '/wp-load.php';\n")

	if !looksLikeCompiledTemplate(twig) {
		t.Error("twig compile head not recognised")
	}
	if !looksLikeCompiledTemplate(smarty) {
		t.Error("smarty compile head not recognised")
	}
	if looksLikeCompiledTemplate(shell) {
		t.Error("webshell head misrecognised as compiled template")
	}
	if looksLikeCompiledTemplate(plain) {
		t.Error("plain php head misrecognised as compiled template")
	}
}

func TestDropperRenameMatch(t *testing.T) {
	c := freshDropperCandidate(time.Unix(1_770_000_000, 0))
	c.Inode = 7001
	c.Size = 1621

	if !dropperRenameMatch(c, 9999, 7001, nil) {
		t.Error("same inode must match regardless of size (rename(2) keeps inode)")
	}
	if !dropperRenameMatch(c, 1621, 8888, c.Head) {
		t.Error("same size + same head must match (copy+delete fallback)")
	}
	if dropperRenameMatch(c, 1621, 8888, []byte("<?php different content")) {
		t.Error("same size but different head must not match")
	}
	if dropperRenameMatch(c, 42, 8888, c.Head) {
		t.Error("different size must not match")
	}
}

func TestAssessDropper(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	cases := []struct {
		name  string
		mut   func(*dropperCandidate)
		probe dropperProbe
		want  dropperVerdict
	}{
		{"file survived ttl", nil, dropperProbe{Exists: true}, dropperBenign},
		{"docroot itself removed", nil, dropperProbe{DocrootGone: true}, dropperBenign},
		{"moved by wp upgrade", nil, dropperProbe{RenamedTo: "/home/alice/public_html/wp-content/plugins/x/x.php"}, dropperBenign},
		{"quarantined by csm", nil, dropperProbe{Quarantined: true}, dropperBenign},
		{"vanished fake plugin", nil, dropperProbe{}, dropperSuspect},
		{"vanished compiled template demoted", func(c *dropperCandidate) {
			c.Head = []byte("<?php\nuse Twig\\Template;\nclass __TwigTemplate_9f8ab12cd34ef56 extends Template {")
		}, dropperProbe{}, dropperDemoted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := freshDropperCandidate(now)
			if tc.mut != nil {
				tc.mut(&c)
			}
			if got := assessDropper(c, tc.probe); got != tc.want {
				t.Errorf("assessDropper() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDropperFlushSingletonAfterGrace(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(3 * time.Minute)

	c := freshDropperCandidate(now)
	tr.HoldGone(c, dropperSuspect, now)

	if got := tr.FlushDue(now.Add(10 * time.Second)); len(got) != 0 {
		t.Fatalf("flush before grace returned %d findings, want 0", len(got))
	}
	got := tr.FlushDue(now.Add(dropperGraceWindow + time.Second))
	if len(got) != 1 {
		t.Fatalf("flush after grace returned %d findings, want 1", len(got))
	}
	f := got[0]
	if f.Aggregate {
		t.Error("singleton must not aggregate")
	}
	if len(f.Items) != 1 || f.Items[0].Cand.Path != c.Path || f.Items[0].Verdict != dropperSuspect {
		t.Errorf("unexpected finding contents: %+v", f)
	}
	if again := tr.FlushDue(now.Add(time.Hour)); len(again) != 0 {
		t.Errorf("second flush must be empty, got %d", len(again))
	}
}

func TestDropperFlushBurstAggregates(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(3 * time.Minute)

	for i := 0; i < dropperBurstThreshold; i++ {
		c := freshDropperCandidate(now)
		c.Path = c.Path + string(rune('a'+i))
		tr.HoldGone(c, dropperSuspect, now.Add(time.Duration(i)*time.Second))
	}
	got := tr.FlushDue(now.Add(dropperGraceWindow + time.Second))
	if len(got) != 1 {
		t.Fatalf("burst returned %d findings, want 1 aggregate", len(got))
	}
	if !got[0].Aggregate {
		t.Error("burst-sized group must aggregate")
	}
	if len(got[0].Items) != dropperBurstThreshold {
		t.Errorf("aggregate carries %d items, want %d", len(got[0].Items), dropperBurstThreshold)
	}
	if got[0].Docroot != "/home/alice/public_html" {
		t.Errorf("aggregate docroot = %q", got[0].Docroot)
	}
}

func TestDropperFlushGroupsPerDocroot(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(3 * time.Minute)

	solo := freshDropperCandidate(now)
	tr.HoldGone(solo, dropperSuspect, now)

	for i := 0; i < dropperBurstThreshold; i++ {
		c := freshDropperCandidate(now)
		c.Docroot = "/home/bob/public_html"
		c.Path = "/home/bob/public_html/wp-content/x" + string(rune('a'+i)) + ".php"
		tr.HoldGone(c, dropperSuspect, now)
	}

	got := tr.FlushDue(now.Add(dropperGraceWindow + time.Second))
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 (one per docroot)", len(got))
	}
	byDocroot := map[string]dropperFinding{}
	for _, f := range got {
		byDocroot[f.Docroot] = f
	}
	if f := byDocroot["/home/alice/public_html"]; f.Aggregate || len(f.Items) != 1 {
		t.Errorf("alice group should be a singleton: %+v", f)
	}
	if f := byDocroot["/home/bob/public_html"]; !f.Aggregate {
		t.Errorf("bob group should aggregate: %+v", f)
	}
}

func TestDropperAlertParams(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)

	t.Run("singleton suspect is critical with evidence", func(t *testing.T) {
		c := freshDropperCandidate(now)
		c.UID = 1004
		c.ProcInfo = "pid=4242 cmd=lsphp uid=1004"
		f := dropperFinding{Docroot: c.Docroot, Items: []dropperGone{{Cand: c, Verdict: dropperSuspect}}}

		sev, msg, details, path := dropperAlertParams(f)
		if sev != alert.Critical {
			t.Errorf("severity = %v, want Critical", sev)
		}
		if !strings.Contains(msg, c.Path) {
			t.Errorf("message %q must name the vanished path", msg)
		}
		if path != c.Path {
			t.Errorf("finding path = %q, want %q", path, c.Path)
		}
		for _, want := range []string{"uid=1004", "1621", "<?php"} {
			if !strings.Contains(details, want) {
				t.Errorf("details %q missing %q", details, want)
			}
		}
	})

	t.Run("demoted compiled template is warning", func(t *testing.T) {
		c := freshDropperCandidate(now)
		c.Head = []byte("<?php class __TwigTemplate_ab12 extends Template {")
		f := dropperFinding{Docroot: c.Docroot, Items: []dropperGone{{Cand: c, Verdict: dropperDemoted}}}
		sev, _, details, _ := dropperAlertParams(f)
		if sev != alert.Warning {
			t.Errorf("severity = %v, want Warning", sev)
		}
		if !strings.Contains(details, "compiled-template") {
			t.Errorf("details %q must explain the demotion", details)
		}
	})

	t.Run("aggregate is warning keyed to docroot", func(t *testing.T) {
		var items []dropperGone
		for i := 0; i < dropperBurstThreshold; i++ {
			c := freshDropperCandidate(now)
			c.Path = c.Path + string(rune('a'+i))
			items = append(items, dropperGone{Cand: c, Verdict: dropperSuspect})
		}
		f := dropperFinding{Aggregate: true, Docroot: "/home/alice/public_html", Items: items}
		sev, msg, details, path := dropperAlertParams(f)
		if sev != alert.Warning {
			t.Errorf("severity = %v, want Warning", sev)
		}
		if !strings.Contains(msg, "8") || !strings.Contains(msg, "/home/alice/public_html") {
			t.Errorf("aggregate message %q must carry count and docroot", msg)
		}
		if path != "/home/alice/public_html" {
			t.Errorf("aggregate path = %q, want docroot", path)
		}
		if !strings.Contains(details, items[0].Cand.Path) {
			t.Errorf("details must sample member paths, got %q", details)
		}
	})

	t.Run("binary head is rendered printable", func(t *testing.T) {
		c := freshDropperCandidate(now)
		c.Path = "/home/alice/public_html/assets/miner"
		c.Mode = 0o100755
		c.Head = []byte("\x7fELF\x02\x01\x01\x00payload")
		f := dropperFinding{Docroot: c.Docroot, Items: []dropperGone{{Cand: c, Verdict: dropperSuspect}}}
		_, _, details, _ := dropperAlertParams(f)
		for _, r := range details {
			if r < 0x20 && r != '\n' && r != '\t' {
				t.Fatalf("details contain raw control byte %q", r)
			}
		}
		if !strings.Contains(details, "ELF") {
			t.Errorf("details should keep printable head bytes, got %q", details)
		}
	})
}

func TestDropperTrackerCapBoundsMemory(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(3 * time.Minute)
	tr.maxTracked = 3

	for i := 0; i < 5; i++ {
		c := freshDropperCandidate(now)
		c.Path = c.Path + string(rune('a'+i))
		tr.Observe(c)
	}
	if got := tr.trackedCount(); got != 3 {
		t.Errorf("tracked %d entries, want cap 3", got)
	}
	if tr.overflowDropped() != 2 {
		t.Errorf("overflowDropped = %d, want 2", tr.overflowDropped())
	}
}
