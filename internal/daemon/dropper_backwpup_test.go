package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

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
