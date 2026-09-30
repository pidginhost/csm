package daemon

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestDropperPluginCopySource(t *testing.T) {
	const docroot = "/home/alice/public_html"
	cases := []struct {
		name, path, docroot, wantRoot string
	}{
		{"site at the docroot", docroot + "/wp-content/mu-plugins/elementor-safe-mode.php", docroot,
			docroot + "/wp-content/plugins/elementor"},
		{"site in a subdirectory", docroot + "/blog/wp-content/mu-plugins/elementor-safe-mode.php", docroot,
			docroot + "/blog/wp-content/plugins/elementor"},
		{"docroot is wp-content", docroot + "/wp-content/mu-plugins/elementor-safe-mode.php", docroot + "/wp-content",
			docroot + "/wp-content/plugins/elementor"},
		{"wp-content outside the docroot", docroot + "/wp-content/mu-plugins/elementor-safe-mode.php", docroot + "/wp-content/mu-plugins", ""},
		{"not under wp-content", docroot + "/content/mu-plugins/elementor-safe-mode.php", docroot, ""},
		{"wp-content suffix is not the directory", docroot + "/old-wp-content/mu-plugins/elementor-safe-mode.php", docroot, ""},
		{"other mu-plugin", docroot + "/wp-content/mu-plugins/loader.php", docroot, ""},
		{"nested below mu-plugins", docroot + "/wp-content/mu-plugins/x/elementor-safe-mode.php", docroot, ""},
		{"plugin directory, not mu-plugins", docroot + "/wp-content/plugins/elementor-safe-mode.php", docroot, ""},
		{"unclean path", docroot + "/wp-content/../wp-content/mu-plugins/elementor-safe-mode.php", docroot, ""},
		{"relative path", "wp-content/mu-plugins/elementor-safe-mode.php", docroot, ""},
		{"sibling docroot sharing a prefix", "/home/alice/public_html_old/wp-content/mu-plugins/elementor-safe-mode.php", docroot, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, pc, ok := dropperPluginCopySource(tc.path, tc.docroot)
			if tc.wantRoot == "" {
				if ok {
					t.Fatalf("mapped to %s, want no plugin source", root)
				}
				return
			}
			if !ok || root != tc.wantRoot || pc.slug != "elementor" ||
				pc.rel != "modules/safe-mode/mu-plugin/elementor-safe-mode.php" {
				t.Fatalf("got root=%q copy=%+v ok=%v, want %s", root, pc, ok, tc.wantRoot)
			}
		})
	}
}

func safeModeCandidate(now time.Time) dropperCandidate {
	c := freshDropperCandidate(now)
	c.Path = c.Docroot + "/wp-content/mu-plugins/elementor-safe-mode.php"
	c.Head = []byte("<?php\n/**\n * Plugin Name: Elementor Safe Mode\n */\nclass Safe_Mode_Example {}\n")
	c.Size, c.Digest = int64(len(c.Head)), sha256.Sum256(c.Head)
	return c
}

func TestAssessDropperPluginCopy(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	cases := []struct {
		name     string
		mutate   func(*dropperCandidate)
		evidence dropperPluginCopyEvidence
		want     dropperVerdict
	}{
		{name: "official release file", evidence: dropperPluginCopyOfficial, want: dropperBenign},
		{name: "installed plugin file", evidence: dropperPluginCopyInstalled, want: dropperDemotedPluginCopy},
		{name: "unproven", evidence: dropperPluginCopyUnproven, want: dropperSuspect},
		{name: "suspicious content", evidence: dropperPluginCopyOfficial, want: dropperSuspect,
			mutate: func(c *dropperCandidate) { c.ContentSuspicious = true }},
		{name: "content rewritten", evidence: dropperPluginCopyOfficial, want: dropperSuspect,
			mutate: func(c *dropperCandidate) { c.ContentRewritten = true }},
		{name: "content rewritten, installed copy", evidence: dropperPluginCopyInstalled, want: dropperSuspect,
			mutate: func(c *dropperCandidate) { c.ContentRewritten = true }},
		{name: "write pending", evidence: dropperPluginCopyOfficial, want: dropperSuspect,
			mutate: func(c *dropperCandidate) { c.WritePending = true }},
		{name: "unsettled read", evidence: dropperPluginCopyInstalled, want: dropperSuspect,
			mutate: func(c *dropperCandidate) { c.ContentUnsettled = true }},
		{name: "digest unknown", evidence: dropperPluginCopyOfficial, want: dropperSuspect,
			mutate: func(c *dropperCandidate) { c.DigestKnown = false }},
		{name: "executable", evidence: dropperPluginCopyInstalled, want: dropperSuspect,
			mutate: func(c *dropperCandidate) { c.Mode |= 0o100 }},
		{name: "not a plugin copy path", evidence: dropperPluginCopyOfficial, want: dropperSuspect,
			mutate: func(c *dropperCandidate) { c.Path = c.Docroot + "/wp-content/mu-plugins/loader.php" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := safeModeCandidate(now)
			if tc.mutate != nil {
				tc.mutate(&c)
			}
			if got := assessDropper(c, dropperProbe{Conclusive: true, PluginCopy: tc.evidence}); got != tc.want {
				t.Fatalf("assessDropper() = %v, want %v", got, tc.want)
			}
		})
	}
}

// Official bytes written over a payload in the same inode cannot account for
// what the payload ran. Every nonempty snapshot is compared, in any order the
// analyzer workers deliver them, and replayed verdicts do not count as writes.
func TestDropperPluginCopyHistory(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	official := safeModeCandidate(now.Add(time.Second))
	payload := official
	payload.Observed = now
	payload.Head = []byte("<?php\n/**\n * Plugin Name: Elementor Safe Mode\n */\nsystem($_POST['c']);\n")
	payload.Size, payload.Digest = int64(len(payload.Head)), sha256.Sum256(payload.Head)
	for _, order := range [][2]int{{0, 1}, {1, 0}} {
		snapshots := []dropperCandidate{payload, official}
		tr := newDropperTracker(time.Minute)
		for _, i := range order {
			if !tr.Refresh(snapshots[i]) {
				tr.Observe(snapshots[i])
			}
		}
		due := tr.Due(now.Add(2 * time.Minute))
		if len(due) != 1 || !due[0].ContentRewritten {
			t.Fatalf("order %v: payload history lost: %+v", order, due)
		}
		if got := assessDropper(due[0], dropperProbe{Conclusive: true, PluginCopy: dropperPluginCopyOfficial}); got != dropperSuspect {
			t.Fatalf("order %v: rewritten copy graded %v", order, got)
		}
	}

	tr := newDropperTracker(time.Minute)
	tr.Observe(official)
	tr.Refresh(official)
	due := tr.Due(now.Add(2 * time.Minute))
	if len(due) != 1 || due[0].ContentRewritten {
		t.Fatalf("replayed snapshot counted as a rewrite: %+v", due)
	}
}

func TestDropperPluginCopyAlertNamesInstalledFile(t *testing.T) {
	c := safeModeCandidate(time.Unix(1_770_000_000, 0))
	sev, _, details, path := dropperAlertParams(dropperFinding{Items: []dropperGone{{Cand: c, Verdict: dropperDemotedPluginCopy}}})
	want := c.Docroot + "/wp-content/plugins/elementor/modules/safe-mode/mu-plugin/elementor-safe-mode.php"
	if sev != alert.Warning || path != c.Path || !strings.Contains(details, want) {
		t.Fatalf("got sev=%v path=%q details=%q, want Warning naming %s", sev, path, details, want)
	}
}

func TestDropperPluginCopyCannotBorrowOtherExemptions(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	for _, tc := range []struct {
		name  string
		body  string
		probe dropperProbe
		want  dropperVerdict
	}{
		{"known probe matches installed file", dropperUploadExecutionProbes[0],
			dropperProbe{Conclusive: true, PluginCopy: dropperPluginCopyInstalled}, dropperDemotedPluginCopy},
		{"known probe has no package proof", dropperUploadExecutionProbes[0],
			dropperProbe{Conclusive: true}, dropperSuspect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := safeModeCandidate(now)
			c.Head = []byte(tc.body)
			c.Size, c.Digest = int64(len(c.Head)), sha256.Sum256(c.Head)
			c = ownDropperCandidate(c)
			if got := assessDropper(c, tc.probe); got != tc.want {
				t.Fatalf("verdict = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDropperPluginCopyRewrittenHistoryStaysCritical(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := safeModeCandidate(now)
	c.ContentRewritten = true
	for _, p := range []dropperProbe{
		{Conclusive: true, ParentRemoved: true, PluginCopy: dropperPluginCopyOfficial},
		{Conclusive: true, DocrootRemoved: true, PluginCopy: dropperPluginCopyInstalled},
	} {
		if got := assessDropper(c, p); got != dropperSuspect {
			t.Fatalf("probe %+v: verdict = %v, want suspect", p, got)
		}
	}
}
