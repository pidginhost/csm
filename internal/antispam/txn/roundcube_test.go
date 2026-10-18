package txn

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

func TestRoundcubeTogglesDoNotReloadServices(t *testing.T) {
	f := newFake(t)
	s := learningApply(f)
	wantOK(t, f.host().Apply(s))
	for _, on := range []bool{true, true, false, false} {
		f.reset()
		s.Roundcube = on
		r := f.host().Apply(s)
		wantOK(t, r)
		want := "<absent>"
		if on {
			want = antispam.RenderRoundcube()
		}
		if f.file(antispam.RoundcubeIncludePath) != want {
			t.Fatalf("Roundcube on=%t: include does not match", on)
		}
		if f.file(antispam.RecordPath) != string(antispam.EncodeRecord(r.Generation)) {
			t.Fatal("completion record does not match the result")
		}
		if f.count("systemctl reload") != 0 || f.count(BuildEximConf) != 0 {
			t.Fatal("Roundcube toggle reloaded a service or rebuilt Exim")
		}
	}
}

func TestRoundcubeTransactionRollback(t *testing.T) {
	for _, operation := range []string{"install", "enable", "disable", "remove"} {
		for _, failure := range []string{"include", "completion"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				f := newFake(t)
				s := learningApply(f)
				s.Roundcube = operation == "disable" || operation == "remove"
				if operation != "install" {
					wantOK(t, f.host().Apply(s))
				}
				before := f.state()
				f.reset()
				s.Roundcube = operation != "disable"
				h := f.host()
				failed := false
				h.replace = func(p string, want, next fileState) error {
					if err := replaceFile(p, want, next); err != nil {
						return err
					}
					include := p == f.root+antispam.RoundcubeIncludePath
					complete := p == f.root+antispam.RecordPath && next.content != string(antispam.EncodeRecord(""))
					if !failed && (failure == "include" && include || failure == "completion" && complete) {
						failed = true
						return errDurability
					}
					return nil
				}
				var r antispam.Result
				if operation == "remove" {
					r = h.Remove()
				} else {
					r = h.Apply(s)
				}
				step := StepRoundcube
				if failure == "completion" {
					step = StepComplete
				}
				if !failed || r.OK || r.FailedStep != step || r.Rollback != antispam.RollbackVerified {
					t.Fatalf("result %+v, failure injected=%t", r, failed)
				}
				if !maps.Equal(f.state(), before) {
					t.Fatal("rollback did not restore every target and the completion record")
				}
				if operation == "enable" || operation == "disable" {
					if f.count("systemctl reload") != 0 || f.count(BuildEximConf) != 0 {
						t.Fatal("include-only rollback reloaded a service or rebuilt Exim")
					}
				}
			})
		}
	}
}

// roundcubeState is what cPanel's PHP prints for the files on disk: the
// include's folder when it holds CSM's text, cPanel's INBOX.Trash otherwise,
// and a later include's junk_mbox when set.
func (f *fakeHost) roundcubeState() string {
	junk, spam := "INBOX.Trash", ""
	if st, _ := readFile(f.root + antispam.RoundcubeIncludePath); st.exists && strings.Contains(st.content, "'INBOX.spam'") {
		junk, spam = "INBOX.spam", "INBOX.spam"
	}
	if f.roundcubeOverride != "" {
		junk = f.roundcubeOverride
	}
	return "junk_mbox=" + junk + "\nspam_mbox=" + spam + "\nmarkasjunk=1\n"
}

func roundcubeApply(f *fakeHost) antispam.Settings {
	s := learningApply(f)
	s.Roundcube = true
	return s
}

func TestRoundcubeVerifyApplied(t *testing.T) {
	f := newFake(t)
	r := f.host().Apply(roundcubeApply(f))
	wantOK(t, r)
	if r.Roundcube != "" || f.file(antispam.RoundcubeIncludePath) != antispam.RenderRoundcube() {
		t.Fatalf("result %+v, include %q", r, f.file(antispam.RoundcubeIncludePath))
	}
	if f.count("env DNS=localhost /usr/local/cpanel/3rdparty/bin/php") != 1 {
		t.Fatal("the include was not verified through cPanel's PHP")
	}
	if st, _ := readFile(f.root + antispam.RoundcubeIncludePath); st.perm != 0o644 {
		t.Fatalf("include mode %v", st.perm)
	}
}

// Another include sorting later resets junk_mbox: the include comes back
// out, learning stays on and the result says why.
func TestRoundcubeVerifyLaterOverride(t *testing.T) {
	f := newFake(t)
	f.roundcubeOverride = "INBOX.Trash"
	s := roundcubeApply(f)
	r := f.host().Apply(s)
	wantOK(t, r)
	if !strings.HasPrefix(r.Roundcube, "unavailable: ") || !strings.Contains(r.Roundcube, `"INBOX.Trash"`) {
		t.Fatalf("result Roundcube = %q, want the loaded junk folder", r.Roundcube)
	}
	if f.file(antispam.RoundcubeIncludePath) != "<absent>" {
		t.Fatal("unverified include left in place")
	}
	for _, p := range antispam.LearningPaths() {
		if st, _ := readFile(f.root + p); !st.exists {
			t.Fatalf("rspamd learning file %s rolled back with the include", p)
		}
	}
	noRC := s
	noRC.Roundcube = false
	noRC.LearningKeys = f.learning
	managed, err := antispam.ManagedContent(noRC)
	if err != nil {
		t.Fatal(err)
	}
	if r.Generation != antispam.Generation(managed) || f.file(antispam.RecordPath) != string(antispam.EncodeRecord(r.Generation)) {
		t.Fatal("record does not describe what is installed without the include")
	}
}

func TestRoundcubeRemoveVerifiesAbsence(t *testing.T) {
	f := newFake(t)
	s := roundcubeApply(f)
	wantOK(t, f.host().Apply(s))
	f.reset()
	s.Roundcube = false
	r := f.host().Apply(s)
	wantOK(t, r)
	if f.file(antispam.RoundcubeIncludePath) != "<absent>" || r.Roundcube != "" {
		t.Fatalf("result %+v", r)
	}
	if f.count("env DNS=localhost /usr/local/cpanel/3rdparty/bin/php") != 1 {
		t.Fatal("removal was not verified")
	}
	// Another include still routing Junk to INBOX.spam is reported, and
	// CSM restores nothing for it.
	wantOK(t, f.host().Apply(roundcubeApply(f)))
	f.reset()
	f.roundcubeOverride = "INBOX.spam"
	r = f.host().Apply(s)
	wantOK(t, r)
	if !strings.HasPrefix(r.Roundcube, "unavailable: ") || f.file(antispam.RoundcubeIncludePath) != "<absent>" {
		t.Fatalf("result %+v, include %q", r, f.file(antispam.RoundcubeIncludePath))
	}
}

func TestRoundcubeForeignFileUntouched(t *testing.T) {
	f := newFake(t)
	foreign := "<?php\n$config['junk_mbox'] = 'Junk';\n"
	writeTest(t, f.root+antispam.RoundcubeIncludePath, foreign, 0o644)
	r := f.host().Apply(learningApply(f))
	wantOK(t, r)
	if f.file(antispam.RoundcubeIncludePath) != foreign {
		t.Fatal("foreign include changed")
	}
}

func TestRoundcubeStagingNameNotGlobbed(t *testing.T) {
	f := newFake(t)
	tmp, err := stageFile(f.root+antispam.RoundcubeIncludePath, "x")
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(tmp.Name())
	discardTemp(tmp)
	if ok, _ := filepath.Match("*.php", name); ok || strings.HasSuffix(name, ".php") {
		t.Fatalf("staging name %q matches Roundcube's *.php glob", name)
	}
}

// An rspamd verification failure rolls back before the include is ever
// written; the include keeps its prior state.
func TestRoundcubeEnclosingRollbackRestores(t *testing.T) {
	f := newFake(t)
	s := roundcubeApply(f)
	wantOK(t, f.host().Apply(s))
	before := f.state()
	f.reset()
	// A score change reloads rspamd, whose learning check then fails.
	f.spamWeight = 20
	s.Roundcube, s.TagScore = false, 7
	r := f.host().Apply(s)
	if r.OK || r.FailedStep != antispam.LearningCheckStep {
		t.Fatalf("result = %+v", r)
	}
	if !maps.Equal(before, f.state()) {
		t.Fatal("failed apply left the include or other files changed")
	}
}

// A crash between the include write and the record leaves an owned include
// without a record; learning off still removes it.
func TestRoundcubeOrphanRemovedWithoutRecord(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	writeTest(t, f.root+antispam.RoundcubeIncludePath, antispam.RenderRoundcube(), 0o644)
	f.reset()
	wantOK(t, f.host().Apply(enforce()))
	if f.file(antispam.RoundcubeIncludePath) != "<absent>" {
		t.Fatal("orphaned include left in place")
	}
	writeTest(t, f.root+antispam.RoundcubeIncludePath, antispam.RenderRoundcube(), 0o644)
	if err := os.Remove(f.root + antispam.RecordPath); err != nil {
		t.Fatal(err)
	}
	f.reset()
	wantOK(t, f.host().Remove())
	if f.file(antispam.RoundcubeIncludePath) != "<absent>" {
		t.Fatal("remove without a record left the include")
	}
}
