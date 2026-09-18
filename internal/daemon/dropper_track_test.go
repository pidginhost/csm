package daemon

import (
	"crypto/sha256"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/wpcheck"
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

func TestDropperTrackerHeadBudgetStaysBoundedAtFullCapacity(t *testing.T) {
	if got := dropperMaxTracked * dropperTrackedHeadMax; got != dropperTrackedHeadBudget {
		t.Fatalf("retained head budget = %d bytes, want %d", got, dropperTrackedHeadBudget)
	}
	if dropperTrackedHeadMax != 1024 {
		t.Fatalf("tracked head window = %d bytes, want 1024", dropperTrackedHeadMax)
	}
}

func TestMergeDropperCandidateKeepsOnlyConsistentParentIdentity(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	prev := freshDropperCandidate(now)
	prev.Parent = dropperParentIdentity{Device: 1, Inode: 2}
	next := prev
	next.Parent = dropperParentIdentity{Device: 1, Inode: 2, BirthNanos: 3, BirthKnown: true}
	if got := mergeDropperCandidate(prev, next).Parent; got != next.Parent {
		t.Fatalf("strengthened parent identity = %+v, want %+v", got, next.Parent)
	}

	next.Parent.Inode++
	conflicted := mergeDropperCandidate(prev, next)
	if conflicted.Parent.known() || !conflicted.Parent.Conflicted {
		t.Fatalf("conflicting parent identity survived merge: %+v", conflicted.Parent)
	}
	if got := mergeDropperCandidate(conflicted, next).Parent; got.known() || !got.Conflicted {
		t.Fatalf("later refresh restored conflicting parent evidence: %+v", got)
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

func TestDropperMergeLateCreateRetainsCloseEvidence(t *testing.T) {
	closed := freshDropperCandidate(time.Now())
	created := closed
	created.Observed = closed.Observed.Add(time.Second)
	created.WritePending = true
	if mergeDropperCandidate(closed, created).WritePending {
		t.Fatal("a delayed CREATE erased the already observed CLOSE_WRITE")
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

func TestWPUpgradeInstallDestinations(t *testing.T) {
	cases := []struct {
		name string
		path string
		want []string
	}{
		{
			"package tree keeps plugin and theme destinations",
			"/home/alice/public_html/wp-content/upgrade/hello-dolly-a1b2/hello-dolly/hello.php",
			[]string{
				"/home/alice/public_html/wp-content/plugins/hello-dolly/hello.php",
				"/home/alice/public_html/wp-content/themes/hello-dolly/hello.php",
			},
		},
		{
			"core language pack unpacks flat",
			"/home/alice/public_html/wp-content/upgrade/wordpress-7.1-ro_ro/admin-ro_RO.l10n.php",
			[]string{
				"/home/alice/public_html/wp-content/languages/admin-ro_RO.l10n.php",
				"/home/alice/public_html/wp-content/languages/plugins/admin-ro_RO.l10n.php",
				"/home/alice/public_html/wp-content/languages/themes/admin-ro_RO.l10n.php",
			},
		},
		{
			"plugin language pack below docroot",
			"/home/alice/public_html/shop/wp-content/upgrade/wordpress-seo-28.5-ro_ro/wordpress-seo-ro_RO.l10n.php",
			[]string{
				"/home/alice/public_html/shop/wp-content/languages/wordpress-seo-ro_RO.l10n.php",
				"/home/alice/public_html/shop/wp-content/languages/plugins/wordpress-seo-ro_RO.l10n.php",
				"/home/alice/public_html/shop/wp-content/languages/themes/wordpress-seo-ro_RO.l10n.php",
			},
		},
		{
			"core update version probe",
			"/home/alice/public_html/wp-content/upgrade/version-current.php",
			[]string{"/home/alice/public_html/wp-includes/version.php"},
		},
		{
			"other loose upgrade file",
			"/home/alice/public_html/wp-content/upgrade/loose.php",
			nil,
		},
		{
			"flat traversal component",
			"/home/alice/public_html/wp-content/upgrade/../evil.php",
			nil,
		},
		{
			"not under upgrade dir",
			"/home/alice/public_html/wp-content/languages/admin-ro_RO.l10n.php",
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := wpUpgradeInstallDestinations(tc.path, "/home/alice/public_html")
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("destination[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
	if got := wpUpgradeInstallDestinations("/home/bob/public_html/wp-content/upgrade/version-current.php", "/home/alice/public_html"); got != nil {
		t.Fatalf("destination outside docroot = %v, want nil", got)
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

func TestTrackedHeadContainsRepresentativeTemplateMarkers(t *testing.T) {
	twig := []byte("<?php\n" + strings.Join([]string{
		"use Twig\\Environment;",
		"use Twig\\Error\\LoaderError;",
		"use Twig\\Error\\RuntimeError;",
		"use Twig\\Extension\\SandboxExtension;",
		"use Twig\\Markup;",
		"use Twig\\Sandbox\\SecurityError;",
		"use Twig\\Sandbox\\SecurityNotAllowedTagError;",
		"use Twig\\Sandbox\\SecurityNotAllowedFilterError;",
		"use Twig\\Sandbox\\SecurityNotAllowedFunctionError;",
		"use Twig\\Source;",
		"use Twig\\Template;",
	}, "\n") + "\n/* templates/admin/dashboard.html.twig */\n" +
		"class __TwigTemplate_9f8ab12cd34ef56 extends Template\n{")
	smarty := []byte("<?php\n/* Smarty version 4.3.1, created on 2026-07-19 17:27:12\n" +
		"  from 'file:/usr/local/cpanel/base/frontend/jupiter/index.tpl' */\n")
	for name, body := range map[string][]byte{"twig": twig, "smarty": smarty} {
		t.Run(name, func(t *testing.T) {
			if len(body) > dropperTrackedHeadMax {
				t.Fatalf("representative header is %d bytes, exceeds %d-byte retained window", len(body), dropperTrackedHeadMax)
			}
			if !looksLikeCompiledTemplate(body) {
				t.Fatal("compiled-template markers were not recognized in retained head")
			}
		})
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
		{"language pack copied into languages dir", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/wp-content/upgrade/wordpress-seo-28.5-ro_ro/wordpress-seo-ro_RO.l10n.php"
			c.WPInstallData = true
		}, dropperProbe{
			Conclusive:   true,
			RenamedTo:    "/home/alice/public_html/wp-content/languages/plugins/wordpress-seo-ro_RO.l10n.php",
			RenameTarget: copiedFileStateAt(freshDropperCandidate(now), "/home/alice/public_html/wp-content/languages/plugins/wordpress-seo-ro_RO.l10n.php"),
		}, dropperBenign},
		{"core version probe matches installed version file", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/wp-content/upgrade/version-current.php"
			c.WPInstallData = true
		}, dropperProbe{
			Conclusive:   true,
			RenamedTo:    "/home/alice/public_html/wp-includes/version.php",
			RenameTarget: copiedFileStateAt(freshDropperCandidate(now), "/home/alice/public_html/wp-includes/version.php"),
		}, dropperBenign},
		{"flat upgrade dropper with different installed copy", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/wp-content/upgrade/wordpress-seo-28.5-ro_ro/wordpress-seo-ro_RO.l10n.php"
			c.WPInstallData = true
		}, dropperProbe{
			Conclusive: true,
			RenamedTo:  "/home/alice/public_html/wp-content/languages/plugins/wordpress-seo-ro_RO.l10n.php",
			RenameTarget: &dropperFileState{
				Path:   "/home/alice/public_html/wp-content/languages/plugins/wordpress-seo-ro_RO.l10n.php",
				Device: 41, Inode: 9001, Size: 1621, Digest: sha256.Sum256([]byte("other")), DigestKnown: true,
			},
		}, dropperSuspect},
		{"vanished flat upgrade dropper stays critical", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/wp-content/upgrade/wordpress-seo-28.5-ro_ro/shell.php"
		}, dropperProbe{Conclusive: true}, dropperSuspect},
		{"vanished version probe without installed copy stays critical", func(c *dropperCandidate) {
			c.Path = "/home/alice/public_html/wp-content/upgrade/version-current.php"
		}, dropperProbe{Conclusive: true}, dropperSuspect},
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

// copiedFileStateAt is a copy-delete destination: another inode holding the
// candidate's exact bytes.
func copiedFileStateAt(c dropperCandidate, path string) *dropperFileState {
	return &dropperFileState{
		Path: path, Device: c.Device, Inode: c.Inode + 1000, Size: c.Size,
		Digest: c.Digest, DigestKnown: c.DigestKnown,
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
		c.Path += string(rune('a' + i))
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
			c.Path += string(rune('a' + i))
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
		c.Path += string(rune('a' + i))
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

// Official release evidence only covers the version file a core update reads
// from the upgrade directory, and only a data snapshot that stayed clean.
func TestDropperOfficialVersionProbeScope(t *testing.T) {
	const docroot = "/home/exampleuser/public_html"
	eligible := func() dropperCandidate {
		c := freshDropperCandidate(time.Unix(1_770_000_000, 0))
		c.Docroot = docroot
		c.Path = docroot + "/wp-content/upgrade/version-current.php"
		c.WPInstallData = true
		c.WPCoreRelease = &wpcheck.Verification{Kind: wpcheck.KindCore, Version: "7.1", Locale: "ro_RO"}
		return c
	}
	verified := dropperProbe{Conclusive: true, OfficialWPCoreFile: true}
	if got := assessDropper(eligible(), verified); got != dropperBenign {
		t.Fatalf("verified version probe = %v, want benign", got)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*dropperCandidate, *dropperProbe)
	}{
		{"not verified", func(_ *dropperCandidate, p *dropperProbe) { p.OfficialWPCoreFile = false }},
		{"no release", func(c *dropperCandidate, _ *dropperProbe) { c.WPCoreRelease = nil }},
		{"translation path", func(c *dropperCandidate, _ *dropperProbe) {
			c.Path = docroot + "/wp-content/upgrade/stage/version-current.l10n.php"
		}},
		{"nested version name", func(c *dropperCandidate, _ *dropperProbe) {
			c.Path = docroot + "/wp-content/upgrade/stage/version-current.php"
		}},
		{"uploads", func(c *dropperCandidate, _ *dropperProbe) {
			c.Path = docroot + "/wp-content/uploads/version-current.php"
		}},
		{"not data", func(c *dropperCandidate, _ *dropperProbe) { c.WPInstallData = false }},
		{"earlier unsafe snapshot", func(c *dropperCandidate, _ *dropperProbe) { c.WPInstallUnsafe = true }},
		{"no digest", func(c *dropperCandidate, _ *dropperProbe) { c.DigestKnown = false }},
		{"write pending", func(c *dropperCandidate, _ *dropperProbe) { c.WritePending = true }},
		{"content verdict", func(c *dropperCandidate, _ *dropperProbe) { c.ContentSuspicious = true }},
		{"executable", func(c *dropperCandidate, _ *dropperProbe) { c.Mode = 0o100755 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, p := eligible(), verified
			tc.mutate(&c, &p)
			if got := assessDropper(c, p); got == dropperBenign {
				t.Fatal("official release evidence cleared an ineligible candidate")
			}
		})
	}
}

func TestDropperCoreHistorySurvivesReordering(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	payload := freshDropperCandidate(now)
	payload.Path = payload.Docroot + "/wp-content/upgrade/update/wordpress/wp-content/themes/example/functions.php"
	payload.Created, payload.WritePending = true, true
	empty := payload
	empty.Observed, empty.Size, empty.Head = now.Add(time.Second), 0, nil
	empty.Digest, empty.DigestKnown = sha256.Sum256(nil), true
	empty.WritePending = false
	official := payload
	official.Observed, official.WritePending = now.Add(2*time.Second), false
	official.Head = []byte("<?php function theme_setup() { add_theme_support('wp-block-styles'); }")
	official.Size, official.Digest = int64(len(official.Head)), sha256.Sum256(official.Head)
	official.CoreMD5Known = true
	for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		snapshots := []dropperCandidate{payload, empty, official}
		tr := newDropperTracker(time.Minute)
		for _, i := range order {
			tr.Observe(snapshots[i])
		}
		// Repeated analyzer verdicts must be idempotent for content history.
		for _, i := range order {
			tr.Refresh(snapshots[i])
		}
		due := tr.Due(now.Add(time.Minute))
		if len(due) != 1 {
			t.Fatalf("order %v: got %d candidates", order, len(due))
		}
		c := due[0]
		if !c.ContentRewritten || c.Digest != official.Digest || !c.Observed.Equal(now) {
			t.Fatalf("order %v lost history, latest snapshot or TTL: %+v", order, c)
		}
		if assessDropper(c, dropperProbe{Conclusive: true, OfficialWPCorePackageFile: true}) == dropperBenign {
			t.Fatalf("order %v hid payload", order)
		}
	}
}

func TestDropperCoreHistoryKeepsInodeGenerations(t *testing.T) {
	for _, knownBirth := range []bool{false, true} {
		now := time.Unix(1_770_000_000, 0)
		payload := freshDropperCandidate(now)
		payload.Path = payload.Docroot + "/wp-content/upgrade/update/wordpress/wp-content/themes/example/functions.php"
		payload.BirthKnown = knownBirth
		official := payload
		official.Observed, official.Birth = now.Add(time.Second), payload.Birth.Add(time.Second)
		official.Head = []byte("<?php function theme_setup() { add_theme_support('wp-block-styles'); }")
		official.Size, official.Digest = int64(len(official.Head)), sha256.Sum256(official.Head)
		official.CoreMD5Known = true
		tr := newDropperTracker(time.Minute)
		tr.Observe(payload)
		if !tr.Refresh(official) {
			tr.Observe(official)
		}
		due := tr.Due(now.Add(2 * time.Minute))
		wantCandidates := 1
		if knownBirth {
			wantCandidates = 2
		}
		if len(due) != wantCandidates {
			t.Fatalf("birth known=%v: got %d candidates", knownBirth, len(due))
		}
		findings := 0
		for _, c := range due {
			if assessDropper(c, dropperProbe{Conclusive: true, OfficialWPCorePackageFile: c.Digest == official.Digest}) != dropperBenign {
				findings++
			}
		}
		if findings != 1 {
			t.Fatalf("birth known=%v: got %d findings, want payload evidence", knownBirth, findings)
		}
	}
}

func TestDropperCoreHistoryRetainsUnknownSnapshot(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := freshDropperCandidate(now)
	c.Path = c.Docroot + "/wp-content/upgrade/update/wordpress/wp-content/themes/example/functions.php"
	c.DigestKnown = false // A nonempty read that exceeded the bound or failed.
	tr := newDropperTracker(time.Minute)
	tr.Observe(c)
	c.Observed = now.Add(time.Second)
	c.DigestKnown, c.CoreMD5Known = true, true
	tr.Refresh(c)
	due := tr.Due(now.Add(time.Minute))
	if len(due) != 1 || !due[0].ContentRewritten {
		t.Fatalf("unknown earlier bytes lost: %+v", due)
	}
	if assessDropper(due[0], dropperProbe{Conclusive: true, OfficialWPCorePackageFile: true}) == dropperBenign {
		t.Fatal("unknown earlier bytes accepted as official")
	}
}

// A staged file whose only snapshot could not be read whole (oversized, or a
// read that raced the writer) was still written once. Moving it into place
// must not be reported as a rewrite; a second snapshot is what proves one.
func TestDropperStagedSingleUnreadableSnapshotIsNotRewrite(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	c := freshDropperCandidate(now)
	c.Path = c.Docroot + "/wp-content/upgrade/example-2.0/example/example.php"
	c.DigestKnown = false
	tr := newDropperTracker(time.Minute)
	tr.Observe(c)
	due := tr.Due(now.Add(time.Minute))
	if len(due) != 1 || due[0].ContentRewritten {
		t.Fatalf("single unreadable snapshot marked rewritten: %+v", due)
	}
	moved := dropperFileState{Path: c.Docroot + "/wp-content/plugins/example/example.php",
		Device: c.Device, Inode: c.Inode, Birth: c.Birth, BirthKnown: c.BirthKnown, IsRegular: true}
	if !dropperRenameMatch(due[0], moved) {
		t.Fatal("rename of a single-write staged file rejected")
	}

	// Once a readable snapshot follows, the unread bytes are unaccounted for.
	tr = newDropperTracker(time.Minute)
	tr.Observe(c)
	c.Observed = now.Add(time.Second)
	c.DigestKnown = true
	if !tr.Refresh(c) {
		t.Fatal("refresh lost candidate")
	}
	due = tr.Due(now.Add(2 * time.Minute))
	if len(due) != 1 || !due[0].ContentRewritten || dropperRenameMatch(due[0], moved) {
		t.Fatalf("unread earlier bytes accepted: %+v", due)
	}
}
