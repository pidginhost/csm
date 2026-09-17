package daemon

import (
	"strings"
	"testing"
	"time"
)

// The upload execution test script as Really Simple Security ships it, before
// and after the plugin's rename. It is copied byte for byte into uploads.
var rssslProbeBodies = []string{
	"<?php\n/**\n * Test file for Really Simple SSL to check if uploads directory has code execution permissions\n *\n */\n\necho \"RSSSL CODE EXECUTION MARKER\";\n",
	"<?php\n/**\n * Test file for Really Simple Security to check if uploads directory has code execution permissions\n *\n */\n\necho \"RSSSL CODE EXECUTION MARKER\";\n",
}

const knownProbePayload = "<?php if (isset($_GET['k'])) { system($_POST['c']); }\n"

func knownProbeTestCandidate(body string) dropperCandidate {
	return dropperCandidate{
		Path:       "/home/exampleuser/public_html/wp-content/uploads/code-execution.php",
		Docroot:    "/home/exampleuser/public_html",
		Observed:   time.Unix(1_770_000_000, 0),
		Birth:      time.Unix(1_770_000_000, 0),
		BirthKnown: true,
		Device:     41,
		Inode:      7004,
		Mode:       0o100644,
		Size:       int64(len(body)),
		PID:        4242,
		Head:       []byte(body),
	}
}

func TestDropperUploadExecutionProbeIsNotADropper(t *testing.T) {
	for _, body := range rssslProbeBodies {
		c := knownProbeTestCandidate(body)
		e := newDropperEngine(dropperEngineConfig{ttl: dropperTestTTL, selfPID: 1})
		if e.admit(c) {
			t.Fatalf("upload execution test script admitted: %q", body)
		}
		owned := ownDropperCandidate(c)
		if got := assessDropper(owned, dropperProbe{Conclusive: true}); got != dropperBenign {
			t.Fatalf("deleted upload execution test script = %v, want benign", got)
		}
	}
}

func TestDropperUploadExecutionProbeLookalikesStillReported(t *testing.T) {
	probe := rssslProbeBodies[1]
	for _, tc := range []struct {
		name   string
		mutate func(*dropperCandidate)
	}{
		{"trailing payload", func(c *dropperCandidate) {
			c.Head = append(c.Head, []byte(knownProbePayload)...)
			c.Size = int64(len(c.Head))
		}},
		{"payload beside marker", func(c *dropperCandidate) {
			c.Head = []byte(strings.Replace(probe, "echo", "system($_GET['c']); echo", 1))
			c.Size = int64(len(c.Head))
		}},
		{"different script same name", func(c *dropperCandidate) {
			c.Head = []byte(knownProbePayload)
			c.Size = int64(len(c.Head))
		}},
		{"prefix of larger file", func(c *dropperCandidate) { c.Size += 4096 }},
		{"trailing newline", func(c *dropperCandidate) {
			c.Head = append(c.Head, '\n')
			c.Size = int64(len(c.Head))
		}},
		{"partial read", func(c *dropperCandidate) { c.Head = c.Head[:len(c.Head)-1] }},
		{"CRLF variant", func(c *dropperCandidate) {
			c.Head = []byte(strings.ReplaceAll(probe, "\n", "\r\n"))
			c.Size = int64(len(c.Head))
		}},
		{"executable mode", func(c *dropperCandidate) { c.Mode = 0o100755 }},
		{"raced read", func(c *dropperCandidate) { c.ContentUnsettled = true }},
		{"earlier code", func(c *dropperCandidate) { c.ContentMayExecute = true }},
		{"content verdict", func(c *dropperCandidate) { c.ContentSuspicious = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := knownProbeTestCandidate(probe)
			tc.mutate(&c)
			e := newDropperEngine(dropperEngineConfig{ttl: dropperTestTTL, selfPID: 1})
			if !e.admit(c) {
				t.Fatal("lookalike upload execution script was not admitted")
			}
			due := e.tr.Due(c.Observed.Add(time.Hour))
			if len(due) != 1 || assessDropper(due[0], dropperProbe{Conclusive: true}) != dropperSuspect {
				t.Fatalf("lookalike deletion not suspect: %+v", due)
			}
		})
	}
}
