package daemon

import (
	"crypto/sha256"
	"runtime"
	"strings"
	"sync"
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

	t.Run("normalizes configured roots", func(t *testing.T) {
		got := dropperDocrootFor(
			"/home/carol/public_html/index.php",
			[]string{"relative/public_html", "/home/carol/public_html/"},
		)
		if got != "/home/carol/public_html" {
			t.Fatalf("dropperDocrootFor() = %q, want normalized absolute root", got)
		}
	})
}

func freshDropperCandidate(now time.Time) dropperCandidate {
	c := dropperCandidate{
		Path:       "/home/alice/public_html/wp-content/plugins/media-opt/media-opt.php",
		Docroot:    "/home/alice/public_html",
		Observed:   now,
		Birth:      now.Add(-2 * time.Second),
		BirthKnown: true,
		Device:     41,
		Inode:      7001,
		Mode:       0o100644,
		Size:       1621,
		PID:        4242,
		Head:       []byte("<?php /* fake plugin loader */ if (isset($_GET['k'])) { system($_POST['c']); }"),
	}
	c.Digest = sha256.Sum256(c.Head)
	c.DigestKnown = true
	return c
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
		}, true},
		{"stale file modified not created", func(c *dropperCandidate) {
			c.Birth = now.Add(-48 * time.Hour)
		}, false},
		{"birth time after observation", func(c *dropperCandidate) {
			c.Birth = now.Add(time.Second)
		}, false},
		{"birth time unavailable", func(c *dropperCandidate) { c.BirthKnown = false }, false},
		{"create event with unavailable birth time", func(c *dropperCandidate) {
			c.BirthKnown = false
			c.Created = true
		}, true},
		{"nonstandard php handler extension", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/uploads/image.jpg"
			c.PHPExecutable = true
		}, true},
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

func TestDropperTrackerDueAtTTLBoundary(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(3 * time.Minute)
	tr.Observe(freshDropperCandidate(now))

	if due := tr.Due(now.Add(3 * time.Minute)); len(due) != 1 {
		t.Fatalf("Due at TTL boundary returned %d entries, want 1", len(due))
	}
}

func TestDropperTrackerOwnsCandidateHead(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(time.Minute)
	c := freshDropperCandidate(now)
	wantHead := string(c.Head)
	tr.Observe(c)

	c.Head[0] = '!'
	due := tr.Due(now.Add(time.Minute + time.Second))
	if len(due) != 1 {
		t.Fatalf("got %d due entries, want 1", len(due))
	}
	if got := string(due[0].Head); got != wantHead {
		t.Fatalf("stored head changed through caller alias: got %q, want %q", got, wantHead)
	}
}

func TestDropperTrackerBoundsCandidateHead(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(time.Minute)
	c := freshDropperCandidate(now)
	c.Head = make([]byte, dropperTrackedHeadMax+1)
	tr.Observe(c)

	due := tr.Due(now.Add(time.Minute))
	if len(due) != 1 || len(due[0].Head) != dropperTrackedHeadMax {
		t.Fatalf("stored head length = %d, want %d", len(due[0].Head), dropperTrackedHeadMax)
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

func TestDropperTrackerCreateThenCloseWithoutBirthTime(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(time.Minute)
	created := freshDropperCandidate(now)
	created.BirthKnown = false
	created.Created = true
	created.Size = 0
	created.Head = nil
	created.DigestKnown = false
	if !shouldTrackDropper(created, 999, 5*time.Minute) {
		t.Fatal("FAN_CREATE candidate without birth time was not admitted")
	}
	tr.Observe(created)

	closed := freshDropperCandidate(now.Add(2 * time.Second))
	closed.BirthKnown = false
	closed.Created = false
	closed.ContentSuspicious = true
	if shouldTrackDropper(closed, 999, 5*time.Minute) {
		t.Fatal("standalone close without create or birth evidence must not be admitted")
	}
	if !tr.Refresh(closed) {
		t.Fatal("close event did not refresh its prior create candidate")
	}

	due := tr.Due(now.Add(time.Minute))
	if len(due) != 1 {
		t.Fatalf("got %d due entries, want 1", len(due))
	}
	if !due[0].Observed.Equal(now) || due[0].Size != closed.Size ||
		string(due[0].Head) != string(closed.Head) || !due[0].Created || !due[0].ContentSuspicious {
		t.Fatalf("create/close candidate was not merged correctly: %+v", due[0])
	}
}

func TestDropperTrackerRefreshDoesNotAdmitUnknownFile(t *testing.T) {
	tr := newDropperTracker(time.Minute)
	if tr.Refresh(freshDropperCandidate(time.Unix(1_770_000_000, 0))) {
		t.Fatal("Refresh admitted a file without a prior create candidate")
	}
}

func TestDropperTrackerRefreshUpgradesBirthIdentity(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(time.Minute)
	created := freshDropperCandidate(now)
	created.BirthKnown = false
	created.Created = true
	tr.Observe(created)

	closed := created
	closed.Observed = now.Add(time.Second)
	closed.Birth = now
	closed.BirthKnown = true
	if !tr.Refresh(closed) {
		t.Fatal("close event with newly available birth time did not refresh create candidate")
	}
	due := tr.Due(now.Add(time.Minute))
	if len(due) != 1 || !due[0].BirthKnown || !due[0].Birth.Equal(now) {
		t.Fatalf("refreshed candidate did not retain stronger birth identity: %+v", due)
	}
}

func TestDropperTrackerOutOfOrderObserveKeepsNewestSnapshot(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(3 * time.Minute)

	older := freshDropperCandidate(now)
	newer := older
	newer.Observed = now.Add(2 * time.Minute)
	newer.Size = 9000
	tr.Observe(newer)
	older.Size = 100
	tr.Observe(older)

	due := tr.Due(now.Add(3 * time.Minute))
	if len(due) != 1 {
		t.Fatalf("got %d due entries, want 1", len(due))
	}
	if !due[0].Observed.Equal(now) || due[0].Size != newer.Size {
		t.Fatalf("due candidate = %+v, want earliest time with newest size %d", due[0], newer.Size)
	}
}

func TestDropperTrackerKeepsReplacementAtSamePath(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(time.Minute)
	first := freshDropperCandidate(now)
	second := first
	second.Inode++
	second.Birth = second.Birth.Add(time.Second)
	second.Observed = second.Observed.Add(time.Second)

	tr.Observe(first)
	tr.Observe(second)
	due := tr.Due(now.Add(time.Minute + time.Second))
	if len(due) != 2 {
		t.Fatalf("same-path replacement produced %d candidates, want 2", len(due))
	}
}

func TestDropperTrackerSeparatesReusedInodeByBirthTime(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(time.Minute)
	first := freshDropperCandidate(now)
	second := first
	second.Birth = second.Birth.Add(time.Second)
	second.Observed = second.Observed.Add(time.Second)

	tr.Observe(first)
	tr.Observe(second)
	if due := tr.Due(now.Add(time.Minute + time.Second)); len(due) != 2 {
		t.Fatalf("reused inode produced %d candidates, want 2", len(due))
	}
}

func TestDropperTrackerConcurrentAnalyzerAndProbe(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(time.Minute)
	const (
		workers   = 8
		perWorker = 32
	)

	start := make(chan struct{})
	done := make(chan struct{})
	probeCount := make(chan int, 1)
	go func() {
		<-start
		count := 0
		for {
			select {
			case <-done:
				count += len(tr.Due(now.Add(time.Hour)))
				probeCount <- count
				return
			default:
				count += len(tr.Due(now.Add(time.Hour)))
				runtime.Gosched()
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func(worker int) {
			defer wg.Done()
			<-start
			for i := 0; i < perWorker; i++ {
				c := freshDropperCandidate(now)
				c.Path += "-" + string(rune('a'+worker)) + string(rune('A'+i))
				tr.Observe(c)
			}
		}(worker)
	}
	close(start)
	wg.Wait()
	close(done)

	if got, want := <-probeCount, workers*perWorker; got != want {
		t.Fatalf("concurrent probe returned %d candidates, want %d", got, want)
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
			"wordpress installed below docroot",
			"/home/alice/public_html/blog/wp-content/upgrade/akismet-x/akismet/akismet.php",
			[]string{
				"/home/alice/public_html/blog/wp-content/plugins/akismet/akismet.php",
				"/home/alice/public_html/blog/wp-content/themes/akismet/akismet.php",
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
		{
			"unclean traversal path",
			"/home/alice/public_html/wp-content/upgrade/stage/plugin/../evil.php",
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := wpUpgradeRenameCandidates(tc.path, "/home/alice/public_html")
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

func TestWPUpgradeRenameCandidatesRejectsUnrelatedRoot(t *testing.T) {
	path := "/home/bob/public_html/wp-content/upgrade/x/y/file.php"
	if got := wpUpgradeRenameCandidates(path, "/home/alice/public_html"); got != nil {
		t.Fatalf("candidate outside docroot = %v, want nil", got)
	}
}

func TestDropperAtomicWriteRenameCandidate(t *testing.T) {
	path := "/home/alice/public_html/.temp.1770000000123.plugin.php"
	if got, want := atomicWriteRenameCandidate(path), "/home/alice/public_html/plugin.php"; got != want {
		t.Fatalf("atomicWriteRenameCandidate() = %q, want %q", got, want)
	}
	if got := atomicWriteRenameCandidate("/home/alice/public_html/plugin.php"); got != "" {
		t.Fatalf("plain path produced rename candidate %q", got)
	}
}

func TestLooksLikeCompiledTemplate(t *testing.T) {
	twig := []byte("<?php\n\nuse Twig\\Environment;\nuse Twig\\Template;\n\n/* tables/browse.twig */\nclass __TwigTemplate_9f8ab12cd34ef56 extends Template\n{")
	smarty := []byte("<?php\n/* Smarty version 4.3.1, created on 2026-07-19 17:27:12\n  from 'index.tpl' */\n")
	shell := []byte("<?php if (isset($_GET['k']) && hash_equals($t,$_GET['k'])) { system($_POST['c']); }")
	plain := []byte("<?php\nrequire __DIR__ . '/wp-load.php';\n")
	markerOnly := []byte("<?php /* __TwigTemplate_ */ system($_POST['c']);")

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
	if looksLikeCompiledTemplate(markerOnly) {
		t.Error("a loose Twig marker must not demote arbitrary PHP")
	}
}

func TestDropperRenameMatch(t *testing.T) {
	c := freshDropperCandidate(time.Unix(1_770_000_000, 0))

	sameInode := dropperFileState{Device: c.Device, Inode: c.Inode, Size: 9999, Birth: c.Birth, BirthKnown: true}
	if !dropperRenameMatch(c, sameInode) {
		t.Error("same device, inode, and birth time must match regardless of size")
	}
	differentDevice := sameInode
	differentDevice.Device++
	if dropperRenameMatch(c, differentDevice) {
		t.Error("same inode number on another filesystem must not match")
	}
	differentBirth := sameInode
	differentBirth.Birth = differentBirth.Birth.Add(time.Second)
	if dropperRenameMatch(c, differentBirth) {
		t.Error("reused inode with a different birth time must not match")
	}
	zeroInode := sameInode
	zeroInode.Inode = 0
	cZero := c
	cZero.Inode = 0
	if dropperRenameMatch(cZero, zeroInode) {
		t.Error("unknown zero inode must not match")
	}
	copyTarget := dropperFileState{Device: c.Device + 1, Inode: 8888, Size: c.Size, Digest: c.Digest, DigestKnown: true}
	if !dropperRenameMatch(c, copyTarget) {
		t.Error("same size and full digest must match a copy-delete fallback")
	}
	copyTarget.Digest = sha256.Sum256([]byte("different content"))
	if dropperRenameMatch(c, copyTarget) {
		t.Error("same size with a different digest must not match")
	}
	copyTarget.Digest = c.Digest
	copyTarget.DigestKnown = false
	if dropperRenameMatch(c, copyTarget) {
		t.Error("a leading-byte snapshot without a full digest must not match")
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
		{"probe not conclusive", nil, dropperProbe{}, dropperInconclusive},
		{"file survived ttl", nil, dropperProbe{Conclusive: true, AtPath: candidateFileState(freshDropperCandidate(now))}, dropperBenign},
		{"replacement exists at path", nil, dropperProbe{Conclusive: true, AtPath: &dropperFileState{
			Path: freshDropperCandidate(now).Path, Device: 41, Inode: 9999,
		}}, dropperSuspect},
		{"docroot itself removed", nil, dropperProbe{Conclusive: true, DocrootRemoved: true}, dropperDemotedDocroot},
		{"unvalidated wp destination", nil, dropperProbe{Conclusive: true, RenamedTo: "/home/alice/public_html/wp-content/plugins/x/x.php"}, dropperSuspect},
		{"matching file at unrelated destination", nil, dropperProbe{
			Conclusive:   true,
			RenamedTo:    "/home/alice/public_html/unrelated/file.php",
			RenameTarget: candidateFileState(freshDropperCandidate(now)),
		}, dropperSuspect},
		{"moved by wp upgrade", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/wp-content/upgrade/staging/y/file.php"
		}, dropperProbe{
			Conclusive:   true,
			RenamedTo:    "/home/alice/public_html/wp-content/plugins/y/file.php",
			RenameTarget: candidateFileStateAt(freshDropperCandidate(now), "/home/alice/public_html/wp-content/plugins/y/file.php"),
		}, dropperBenign},
		{"rename state from wrong path", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/wp-content/upgrade/staging/y/file.php"
		}, dropperProbe{
			Conclusive:   true,
			RenamedTo:    "/home/alice/public_html/wp-content/plugins/y/file.php",
			RenameTarget: candidateFileStateAt(freshDropperCandidate(now), "/home/alice/public_html/unrelated/file.php"),
		}, dropperSuspect},
		{"moved by atomic write", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/.temp.1770000000123.plugin.php"
		}, dropperProbe{
			Conclusive:   true,
			RenamedTo:    "/home/alice/public_html/plugin.php",
			RenameTarget: candidateFileStateAt(freshDropperCandidate(now), "/home/alice/public_html/plugin.php"),
		}, dropperBenign},
		{"quarantined by csm", nil, dropperProbe{Conclusive: true, QuarantineMatched: true}, dropperBenign},
		{"vanished fake plugin", nil, dropperProbe{Conclusive: true}, dropperSuspect},
		{"vanished compiled template demoted", func(c *dropperCandidate) {
			c.Head = []byte("<?php\nuse Twig\\Template;\nclass __TwigTemplate_9f8ab12cd34ef56 extends Template {")
		}, dropperProbe{Conclusive: true}, dropperDemotedTemplate},
		{"content signal defeats template demotion", func(c *dropperCandidate) {
			c.Head = []byte("<?php\nclass __TwigTemplate_9f8ab12cd34ef56 extends Template { system($_POST['c']); }")
			c.ContentSuspicious = true
		}, dropperProbe{Conclusive: true}, dropperSuspect},
		{"vanished atomic stage demoted", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/.temp.1770000000123.plugin.php"
		}, dropperProbe{Conclusive: true}, dropperDemotedAtomicWrite},
		{"content signal defeats atomic stage demotion", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/.temp.1770000000123.plugin.php"
			c.ContentSuspicious = true
		}, dropperProbe{Conclusive: true}, dropperSuspect},
		{"vanished wp upgrade stage demoted", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/wp-content/upgrade/x/y/file.php"
		}, dropperProbe{Conclusive: true}, dropperDemotedWPUpgrade},
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

func candidateFileState(c dropperCandidate) *dropperFileState {
	return candidateFileStateAt(c, c.Path)
}

func candidateFileStateAt(c dropperCandidate, path string) *dropperFileState {
	return &dropperFileState{
		Path:        path,
		Device:      c.Device,
		Inode:       c.Inode,
		Size:        c.Size,
		Birth:       c.Birth,
		BirthKnown:  c.BirthKnown,
		Digest:      c.Digest,
		DigestKnown: c.DigestKnown,
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

func TestDropperFlushAtGraceBoundary(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(time.Minute)
	tr.HoldGone(freshDropperCandidate(now), dropperSuspect, now)

	if got := tr.FlushDue(now.Add(dropperGraceWindow)); len(got) != 1 {
		t.Fatalf("flush at grace boundary returned %d findings, want 1", len(got))
	}
}

func TestDropperTrackerDoesNotHoldNonFindingVerdicts(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(time.Minute)
	tr.HoldGone(freshDropperCandidate(now), dropperBenign, now)
	tr.HoldGone(freshDropperCandidate(now), dropperInconclusive, now)

	if got := tr.FlushDue(now.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("benign candidate produced %d findings, want 0", len(got))
	}
}

func TestDropperFlushBelowBurstKeepsEveryCandidate(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(3 * time.Minute)

	const count = dropperBurstThreshold - 1
	for i := 0; i < count; i++ {
		c := freshDropperCandidate(now)
		c.Path += string(rune('a' + i))
		tr.HoldGone(c, dropperSuspect, now)
	}

	got := tr.FlushDue(now.Add(dropperGraceWindow + time.Second))
	if len(got) != count {
		t.Fatalf("below-threshold flush returned %d findings, want %d", len(got), count)
	}
	for _, f := range got {
		if f.Aggregate || len(f.Items) != 1 {
			t.Fatalf("below-threshold finding must be a singleton: %+v", f)
		}
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

func TestDropperFlushDoesNotHideSuspectInDemotedChurn(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(3 * time.Minute)

	for i := 0; i < dropperBurstThreshold-1; i++ {
		c := freshDropperCandidate(now)
		c.Path += string(rune('a' + i))
		tr.HoldGone(c, dropperDemotedTemplate, now)
	}
	suspect := freshDropperCandidate(now)
	suspect.Path += "-suspect"
	tr.HoldGone(suspect, dropperSuspect, now)

	got := tr.FlushDue(now.Add(dropperGraceWindow))
	if len(got) != dropperBurstThreshold {
		t.Fatalf("mixed churn returned %d findings, want %d separate findings", len(got), dropperBurstThreshold)
	}
	foundSuspect := false
	for _, f := range got {
		if f.Aggregate {
			t.Fatalf("mixed demoted and suspect candidates must not aggregate together: %+v", f)
		}
		if f.Items[0].Verdict == dropperSuspect {
			foundSuspect = true
			if sev, _, _, _ := dropperAlertParams(f); sev != alert.Critical {
				t.Fatalf("suspect mixed with churn has severity %v, want Critical", sev)
			}
		}
	}
	if !foundSuspect {
		t.Fatal("suspect candidate was lost from mixed churn")
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
		f := dropperFinding{Docroot: c.Docroot, Items: []dropperGone{{Cand: c, Verdict: dropperDemotedTemplate}}}
		sev, _, details, _ := dropperAlertParams(f)
		if sev != alert.Warning {
			t.Errorf("severity = %v, want Warning", sev)
		}
		if !strings.Contains(details, "compiled-template") {
			t.Errorf("details %q must explain the demotion", details)
		}
	})

	t.Run("all false-positive demotions remain visible warnings", func(t *testing.T) {
		for _, verdict := range []dropperVerdict{
			dropperDemotedAtomicWrite,
			dropperDemotedWPUpgrade,
			dropperDemotedDocroot,
		} {
			c := freshDropperCandidate(now)
			f := dropperFinding{Docroot: c.Docroot, Items: []dropperGone{{Cand: c, Verdict: verdict}}}
			sev, _, details, _ := dropperAlertParams(f)
			if sev != alert.Warning || !strings.Contains(details, "Demoted:") {
				t.Errorf("verdict %v rendered severity=%v details=%q, want explained Warning", verdict, sev, details)
			}
		}
	})

	t.Run("unclassified aggregate is high keyed to docroot", func(t *testing.T) {
		var items []dropperGone
		for i := 0; i < dropperBurstThreshold; i++ {
			c := freshDropperCandidate(now)
			c.Path = c.Path + string(rune('a'+i))
			items = append(items, dropperGone{Cand: c, Verdict: dropperSuspect})
		}
		f := dropperFinding{Aggregate: true, Docroot: "/home/alice/public_html", Items: items}
		sev, msg, details, path := dropperAlertParams(f)
		if sev != alert.High {
			t.Errorf("severity = %v, want High", sev)
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

	t.Run("classified churn aggregate is warning", func(t *testing.T) {
		var items []dropperGone
		for i := 0; i < dropperBurstThreshold; i++ {
			c := freshDropperCandidate(now)
			c.Path += string(rune('a' + i))
			items = append(items, dropperGone{Cand: c, Verdict: dropperDemotedTemplate})
		}
		f := dropperFinding{Aggregate: true, Docroot: "/home/alice/public_html", Items: items}
		sev, _, _, _ := dropperAlertParams(f)
		if sev != alert.Warning {
			t.Errorf("severity = %v, want Warning", sev)
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

	t.Run("process evidence cannot inject an alert line", func(t *testing.T) {
		c := freshDropperCandidate(now)
		c.ProcInfo = "pid=4242 cmd=worker\nCRITICAL fake"
		f := dropperFinding{Docroot: c.Docroot, Items: []dropperGone{{Cand: c, Verdict: dropperSuspect}}}
		_, _, details, _ := dropperAlertParams(f)
		if strings.Contains(details, "\nCRITICAL fake") {
			t.Fatalf("process info injected a details line: %q", details)
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
		if accepted := tr.Observe(c); accepted != (i < 3) {
			t.Errorf("Observe candidate %d accepted = %v, want %v", i, accepted, i < 3)
		}
	}
	if got := tr.trackedCount(); got != 3 {
		t.Errorf("tracked %d entries, want cap 3", got)
	}
	if tr.overflowDropped() != 2 {
		t.Errorf("overflowDropped = %d, want 2", tr.overflowDropped())
	}
}
