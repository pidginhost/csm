package daemon

import (
	"testing"
	"time"
)

// WordPress and its plugins scatter guard files through upload directories
// and delete them again during imports. On a production host WP All Import
// alone produced 778 self_deleting_dropper_realtime findings in 30 hours from
// one path, and those findings were what promoted an ordinary account to a
// "web_account_compromise" incident.
//
// The distinguishing fact is not the path -- allowlisting a path hands an
// attacker a place to work -- but the content. A file that contains no
// executable statement does nothing when it is included, so it cannot be the
// payload half of a dropper. Demoting on that fact costs no detection: an
// attacker who strips the code out of their dropper has no dropper.
//
// The guard only applies when the retained head covers the whole file. A big
// file whose first bytes are a comment says nothing about the rest.
//
// The eval()/system() strings below are inert fixtures: they are malware
// samples the detector must keep flagging, never executed by this test.
func TestDropperInertContentIsNotADropper(t *testing.T) {
	tests := []struct {
		name  string
		head  string
		size  int64
		inert bool
	}{
		// The actual production false positive: WP All Import writes a
		// zero-byte index.php as a directory guard, then removes it.
		{"empty guard file", "", 0, true},
		// Redux framework's guard file, verbatim from the same host.
		{"open tag and line comment", "<?php\n//Silence is golden", 25, true},
		{"open tag only", "<?php", 5, true},
		{"open tag and block comment", "<?php /* nothing here */", 24, true},
		{"whitespace only", "\n\n  \n", 5, true},

		// wpforms' guard file, verbatim: this one really does run code.
		{"header calls are code", "<?php\nheader( $_SERVER['SERVER_PROTOCOL'] . ' 404 Not Found' );\n", 63, false},
		{"single statement", "<?php echo 1;", 13, false},
		{"eval payload", "<?php eval($_POST['x']);", 24, false},
		// A comment before real code must not fool the scan.
		{"comment then code", "<?php // guard\n@system($_GET['c']);", 35, false},
		// Head truncated: the comment proves nothing about the remaining
		// bytes, so this must stay a candidate.
		{"comment head of a larger file", "<?php // silence", 4096, false},
		// Non-PHP text with no open tag still executes nothing as PHP, but a
		// file that is pure payload for an include is not our call to make
		// here; treat any non-empty non-PHP content as code-bearing.
		{"raw text without open tag", "not php at all", 14, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := dropperContentIsInert([]byte(tc.head), tc.size)
			if got != tc.inert {
				t.Errorf("dropperContentIsInert(%q, size=%d) = %v, want %v", tc.head, tc.size, got, tc.inert)
			}
		})
	}
}

// A file the realtime content pass already flagged must never be demoted by
// a later heuristic, whatever its head looks like.
func TestDropperContentSuspiciousSurvivesInertGate(t *testing.T) {
	e := newDropperEngine(dropperEngineConfig{ttl: dropperTestTTL, selfPID: 1})
	c := inertTestCandidate()
	c.ContentSuspicious = true

	if !e.admit(c) {
		t.Fatal("a content-flagged candidate was demoted as inert")
	}
}

// The gate must actually stop the observed false positive.
func TestDropperEngineRejectsEmptyGuardFile(t *testing.T) {
	e := newDropperEngine(dropperEngineConfig{ttl: dropperTestTTL, selfPID: 1})

	if e.admit(inertTestCandidate()) {
		t.Fatal("zero-byte guard file was admitted as a dropper candidate")
	}
}

// And must not stop a real one.
func TestDropperEngineAdmitsCodeBearingFile(t *testing.T) {
	e := newDropperEngine(dropperEngineConfig{ttl: dropperTestTTL, selfPID: 1})
	c := inertTestCandidate()
	c.Head = []byte("<?php @eval($_POST['x']);")
	c.Size = int64(len(c.Head))

	if !e.admit(c) {
		t.Fatal("a code-bearing self-deleting file was rejected")
	}
}

const dropperTestTTL = 3 * time.Minute

// inertTestCandidate mirrors the production false positive: a zero-byte
// index.php guard file written under an uploads directory and removed again.
func inertTestCandidate() dropperCandidate {
	return dropperCandidate{
		Path:     "/home/alice/public_html/wp-content/uploads/wpallimport/uploads/abc/index.php",
		Docroot:  "/home/alice/public_html",
		Observed: time.Unix(1_770_000_000, 0),
		Created:  true,
		Device:   41,
		Inode:    7002,
		Mode:     0o100644,
		Size:     0,
		PID:      4242,
		Head:     nil,
	}
}
