package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestBackWPupFolderListHeadBoundaries(t *testing.T) {
	for _, eol := range []string{"\n", "\r\n"} {
		for padding := 0; padding < 12; padding++ {
			t.Run(fmt.Sprintf("eol=%q/padding=%d", eol, padding), func(t *testing.T) {
				prefix := "<?php" + eol + "///home/alice/"
				// Shift a line ending and the next comment marker across the
				// actual retention boundary, keeping every folder absolute.
				body := prefix + strings.Repeat("a/", (dropperTrackedHeadMax-len(prefix))/2-4) +
					strings.Repeat("b", padding) + "/" + eol + "///home/alice/next/" + eol
				c := freshDropperCandidate(time.Unix(1_770_000_000, 0))
				c.Path, c.Head, c.Size = backwpupDir+"backwpup-ced7cc-folder.php", []byte(body), int64(len(body))
				c = ownDropperCandidate(c)
				if len(c.Head) != dropperTrackedHeadMax {
					t.Fatalf("head length = %d, want retention limit", len(c.Head))
				}
				if got := assessDropper(c, dropperProbe{Conclusive: true}); got != dropperDemotedBackupState {
					t.Fatalf("verdict = %v, want backup-state demotion; head ends %q", got, c.Head[len(c.Head)-12:])
				}
			})
		}
	}
}

func TestBackWPupEngineRetainsEvidence(t *testing.T) {
	for _, file := range []struct{ name, body string }{
		{"backwpup-working.php", `<?php //{"job":{}}`},
		{"backwpup-ced7cc-folder.php", "<?php\n///home/alice/"},
	} {
		for _, tc := range []struct {
			name, suffix string
			suspicious   bool
			want         alert.Severity
		}{
			{"complete comment", "", false, alert.Warning},
			{"unseen tail", strings.Repeat("x", dropperTrackedHeadMax) + "\necho 1;", false, alert.Warning},
			{"content signal", "", true, alert.Critical},
			{"newline escape", "\necho 1;", false, alert.Critical},
			{"CR escape", "\recho 1;", false, alert.Critical},
			{"CRLF escape", "\r\necho 1;", false, alert.Critical},
			{"closing tag", "?><?=1?>", false, alert.Critical},
			{"attribute escape", "\n#[Attr]\nfunction f() {}\necho 1;", false, alert.Critical},
		} {
			t.Run(file.name+"/"+tc.name, func(t *testing.T) {
				now := time.Unix(1_770_000_000, 0)
				c := freshDropperCandidate(now)
				c.Path, c.Head = backwpupDir+file.name, []byte(file.body+tc.suffix)
				c.Size, c.ContentSuspicious = int64(len(c.Head)), tc.suspicious
				e, alerts := newTestEngine(time.Minute)
				if !e.admit(c) {
					t.Fatal("comment-bearing PHP must remain tracked")
				}
				future := now.Add(2 * time.Minute)
				prober := &fakeProber{}
				e.probeStep(future, prober, future)
				e.probeStep(future.Add(dropperGraceWindow), prober, future.Add(dropperGraceWindow))
				if len(*alerts) != 1 {
					t.Fatalf("emitted %d alerts, want 1", len(*alerts))
				}
				if got := (*alerts)[0]; got.sev != tc.want || got.path != c.Path || got.check != dropperCheckName {
					t.Fatalf("alert = %+v, want %v for %s", got, tc.want, c.Path)
				}
			})
		}
	}
}

// BackWPup keeps a running job's state in uploads/backwpup/<id>/temp/ and
// removes it when the job ends: backwpup-working.php holds the job as JSON
// behind "<?php //", and backwpup-<hash>-folder.php lists absolute folders,
// one "//" comment per line. The tracked head is too short to prove the whole file
// inert, so the evidence loss stays a Warning, not a Critical page.
const (
	backwpupDir       = "/home/alice/public_html/wp-content/uploads/backwpup/ced7cc/temp/"
	backwpupWorking   = `<?php //{"job":{"type":["FILE","WPPLUGIN"],"destinations":["DROPBOX","FOLDER"],"name":"Files and Database Backup","activetype":"wpcron","logfile":"\/home\/alice\/logs\/backwpup_log.html"`
	backwpupFolderRaw = "<?php\n///home/alice/public_html/\n///home/alice/public_html/.well-known/\n///home/alice/public_html/.well-known/acme-challenge/\n///home/alice/public_html/wp-con"
)

func TestLooksLikeBackWPupJobState(t *testing.T) {
	cases := []struct {
		name, path, head string
		want             bool
	}{
		{"working state", backwpupDir + "backwpup-working.php", backwpupWorking, true},
		{"folder list", backwpupDir + "backwpup-ced7cc-folder.php", backwpupFolderRaw, true},
		{"folder list CRLF", backwpupDir + "backwpup-ced7cc-folder.php", strings.ReplaceAll(backwpupFolderRaw, "\n", "\r\n"), true},
		{"other filename", backwpupDir + "cache.php", backwpupWorking, false},
		{"folder content under working name", backwpupDir + "backwpup-working.php", backwpupFolderRaw, false},
		{"working content under folder name", backwpupDir + "backwpup-ced7cc-folder.php", backwpupWorking, false},
		{"code after the comment line", backwpupDir + "backwpup-working.php", `<?php //{"job":{}}` + "\nsystem($_POST['c']);", false},
		{"closing tag inside the comment", backwpupDir + "backwpup-working.php", `<?php //{"job":{"x":"?><?php system($_POST['c']);`, false},
		{"bare CR ends the comment", backwpupDir + "backwpup-working.php", `<?php //{"job":{}}` + "\rsystem($_POST['c']);", false},
		{"code line in folder list", backwpupDir + "backwpup-ced7cc-folder.php", "<?php\n///home/alice/public_html/\nsystem($_POST['c']);\n", false},
		{"attribute line in folder list", backwpupDir + "backwpup-ced7cc-folder.php", "<?php\n///home/alice/public_html/\n#[Attr] function f(){}\n", false},
		{"relative folder", backwpupDir + "backwpup-ced7cc-folder.php", "<?php\n//tmp/x/\n//etc\n", false},
		{"no opening tag", backwpupDir + "backwpup-working.php", `//{"job":{}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeBackWPupJobState(tc.path, []byte(tc.head)); got != tc.want {
				t.Errorf("looksLikeBackWPupJobState() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAssessDropperBackWPupJobStateDemoted(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := freshDropperCandidate(now)
	c.Path, c.Head = backwpupDir+"backwpup-working.php", []byte(backwpupWorking)
	if got := assessDropper(c, dropperProbe{Conclusive: true}); got != dropperDemotedBackupState {
		t.Fatalf("assessDropper() = %v, want dropperDemotedBackupState", got)
	}
	c.ContentSuspicious = true
	if got := assessDropper(c, dropperProbe{Conclusive: true}); got != dropperSuspect {
		t.Fatalf("assessDropper() with a content signal = %v, want dropperSuspect", got)
	}
}

func TestDropperBackWPupJobStateAlertIsWarning(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := freshDropperCandidate(now)
	c.Path, c.Head = backwpupDir+"backwpup-working.php", []byte(backwpupWorking)
	sev, _, details, _ := dropperAlertParams(dropperFinding{Items: []dropperGone{{Cand: c, Verdict: dropperDemotedBackupState}}})
	if sev != alert.Warning {
		t.Errorf("severity = %v, want Warning", sev)
	}
	if !strings.Contains(details, "BackWPup") {
		t.Errorf("details = %q, want the demotion reason", details)
	}
}
