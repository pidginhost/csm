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
// Blank content is the discriminator, not the path. Comment-bearing files
// remain candidates because source-encoding conversion can change their
// tokens before PHP parses them.
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
		// Nonblank guards cannot be exempted without interpreter settings.
		{"open tag and line comment", "<?php\n//Silence is golden", 25, false},
		{"open tag only", "<?php", 5, false},
		{"open tag and block comment", "<?php /* nothing here */", 24, false},
		{"whitespace only", "\n\n  \n", 5, true},
		{"all PHP whitespace", " \t\r\n", 4, true},
		{"Unicode whitespace", "\xc2\xa0", 2, false},
		{"form feed", "\f", 1, false},
		{"blank head of a larger file", " \t\r\n", 4096, false},

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

func TestDropperInertGateDoesNotParseExecutablesAsPHP(t *testing.T) {
	// A shell executes the second line after the first line's redirection
	// fails. PHP instead sees an unterminated comment and executes nothing.
	c := inertTestCandidate()
	c.Path = "/home/alice/public_html/payload.sh"
	c.Mode = 0o100755
	c.Head = []byte("<?php /*\nprintf EXECUTED\n")
	c.Size = int64(len(c.Head))
	e := newDropperEngine(dropperEngineConfig{ttl: dropperTestTTL, selfPID: 1})
	if !e.admit(c) {
		t.Fatal("shell payload rejected using PHP comment syntax")
	}
	due := e.tr.Due(c.Observed.Add(2 * dropperTestTTL))
	if len(due) != 1 || assessDropper(due[0], dropperProbe{Conclusive: true}) != dropperSuspect {
		t.Fatalf("executable payload demoted as an inert PHP guard: %+v", due)
	}
}

func TestDropperInertGateExecutableCarriageReturnIsNotWhitespace(t *testing.T) {
	c := inertTestCandidate()
	c.Mode = 0o100755
	c.Head, c.Size = []byte("\r"), 1
	// A POSIX shell treats CR as a command word, not blank space.
	if dropperCandidateIsInert(c) {
		t.Fatal("executable script discarded using PHP whitespace rules")
	}
}

func TestDropperInertGatePendingWriteIsNotComplete(t *testing.T) {
	c := inertTestCandidate()
	c.WritePending = true
	e := newDropperEngine(dropperEngineConfig{ttl: dropperTestTTL, selfPID: 1})
	if !e.admit(c) {
		t.Fatal("pending create was not admitted")
	}
	// An unlinked file can still have a writer holding it open. Without a
	// close-write snapshot, its initially empty contents prove nothing.
	due := e.tr.Due(c.Observed.Add(2 * dropperTestTTL))
	if len(due) != 1 || assessDropper(due[0], dropperProbe{Conclusive: true}) != dropperSuspect {
		t.Fatalf("unfinished write demoted as an empty guard: %+v", due)
	}
}

func TestDropperInertGatePHPBoundaries(t *testing.T) {
	for _, body := range []string{
		"<?php/*/\r\n?><?php echo 1;",
		"<?php ?><?php echo 1;",
		"<?php ?><?=1?>",
		"<?php // ?><?php echo 1;",
		"<?php # ?><?=1?>",
		"<?php // %><?php echo 1;",
		"<?php # %><%=1%>",
		"<?php // comment\recho 1;",
		"<?php # comment\recho 1;",
		"<?php /* outer /* inner */ echo 1; // */",
		"<?php ?>text<script language=\"php\">echo 1;</script>",
		"<?=1?>",
		"<script language=\"php\">echo 1;</script>",
		"<?php #[Example] function f() {}",
		"\xef\xbb\xbf<?php echo 1;",
		"\xff\xfe<\x00?\x00p\x00h\x00p\x00 \x00",
		"<?php \xc2\xa0// not PHP whitespace",
		"<?php ?>non-PHP payload",
	} {
		t.Run(body, func(t *testing.T) {
			c := inertTestCandidate()
			c.Head, c.Size = []byte(body), int64(len(body))
			if dropperContentIsInert(c.Head, c.Size) {
				t.Fatal("unproven content classified as inert")
			}
			e := newDropperEngine(dropperEngineConfig{ttl: dropperTestTTL, selfPID: 1})
			if !e.admit(c) {
				t.Fatal("potential payload rejected by admission gate")
			}
		})
	}
	for _, body := range []string{
		"<?php // guard\r# guard\r\n/* guard */ ?> \n",
		"<?php /* ?> <?=1?> */",
		"<?php /* unterminated <?=1?>",
	} {
		if dropperContentIsInert([]byte(body), int64(len(body))) {
			t.Errorf("comment-only guard exempted without interpreter settings: %q", body)
		}
	}
	head := []byte("<?php // guard")
	for _, size := range []int64{-1, int64(len(head) + 1), 4096} {
		if dropperContentIsInert(head, size) {
			t.Errorf("incomplete head classified as inert at size %d", size)
		}
	}
}

func TestDropperInertGateRejectsSourceEncodingAmbiguity(t *testing.T) {
	for _, body := range []string{
		"<?php // non-ASCII \x85echo 1;",
		"<?php /* non-ASCII \xc2\xa0 */",
		// UTF-7 and its IMAP variant can encode newlines or comment
		// terminators using only ASCII bytes before PHP tokenizes them.
		"<?php // +AAo-echo 1;",
		"<?php /* +ACoALw-echo 1; /* */",
		"<?php // &AAo-echo 1;",
		// PHP also accepts transfer encodings as source encodings.
		"<?php // =0Aecho 1;",
		"<?php //AAAPD9waHAgZWNobyAxOyAg",
		// Stateful encodings and wide characters cannot be proven inert
		// without knowing the interpreter's source-encoding settings.
		"<?php /* \x1b$B text */",
		"<?php /* ~{ text */",
		"<?php // \x00 text",
	} {
		t.Run(body, func(t *testing.T) {
			c := inertTestCandidate()
			c.Head, c.Size = []byte(body), int64(len(body))
			if dropperCandidateIsInert(c) {
				t.Fatal("encoding-dependent content classified as inert")
			}
			e := newDropperEngine(dropperEngineConfig{ttl: dropperTestTTL, selfPID: 1})
			if !e.admit(c) {
				t.Fatal("encoding-dependent candidate rejected")
			}
		})
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
