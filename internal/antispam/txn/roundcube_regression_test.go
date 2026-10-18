package txn

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

const roundcubePHPCommand = "setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs env DNS=localhost /usr/local/cpanel/3rdparty/bin/php"

func TestRoundcubeRemovalReportsVerification(t *testing.T) {
	for _, operation := range []string{"disable", "remove"} {
		for _, tc := range []struct {
			name, output string
			err          error
			unavailable  bool
		}{
			{"removed", "junk_mbox=INBOX.Trash\nspam_mbox=\nmarkasjunk=1\n", nil, false},
			{"PHP failure", "", errors.New("PHP failed"), true},
			{"junk override", "junk_mbox=INBOX.spam\nspam_mbox=\nmarkasjunk=1\n", nil, true},
			{"plugin override", "junk_mbox=INBOX.Trash\nspam_mbox=INBOX.spam\nmarkasjunk=1\n", nil, true},
		} {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				f := newFake(t)
				s := roundcubeApply(f)
				wantOK(t, f.host().Apply(s))
				f.reset()
				h := f.host()
				h.run = func(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
					r := f.run(ctx, limit, name, args...)
					if strings.HasPrefix(name+" "+strings.Join(args, " "), roundcubePHPCommand) {
						return antispam.CommandResult{Stdout: tc.output, Err: tc.err}
					}
					return r
				}
				var r antispam.Result
				if operation == "remove" {
					r = h.Remove()
					if f.file(antispam.RecordPath) != "<absent>" {
						t.Error("removal kept the completion record")
					}
				} else {
					s.Roundcube = false
					r = h.Apply(s)
					if f.count("systemctl reload") != 0 || f.count(BuildEximConf) != 0 {
						t.Error("include removal reloaded services")
					}
				}
				wantOK(t, r)
				if strings.HasPrefix(r.Roundcube, antispam.RoundcubeUnavailable) != tc.unavailable {
					t.Errorf("Roundcube = %q, want unavailable=%t", r.Roundcube, tc.unavailable)
				}
				if f.file(antispam.RoundcubeIncludePath) != "<absent>" || f.count(roundcubePHPCommand) != 1 {
					t.Fatal("include removal was undone or not verified once")
				}
			})
		}
	}
}

func TestRoundcubeFailedUpdateRecordsRestoredInclude(t *testing.T) {
	for _, phpFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "override", true: "PHP failure"}[phpFails], func(t *testing.T) {
			f := newFake(t)
			s := roundcubeApply(f)
			wantOK(t, f.host().Apply(s))
			prior := antispam.RenderRoundcube() + "// prior owned content\n"
			writeTest(t, f.root+antispam.RoundcubeIncludePath, prior, 0o640)
			f.reset()
			f.roundcubeOverride = "INBOX.Trash"
			if phpFails {
				f.fail[roundcubePHPCommand] = []int{1}
			}
			s.TagScore++
			h := f.host()
			r := h.Apply(s)
			wantOK(t, r)
			if !strings.HasPrefix(r.Roundcube, antispam.RoundcubeUnavailable) {
				t.Fatalf("missing include warning: %+v", r)
			}
			st, err := readFile(f.root + antispam.RoundcubeIncludePath)
			if err != nil || st.content != prior || st.perm != 0o640 {
				t.Fatal("the prior owned include and its mode were not restored")
			}
			want := antispam.Generation(antispam.InstalledContent(h.targets()))
			if r.Generation != want || f.file(antispam.RecordPath) != string(antispam.EncodeRecord(want)) {
				t.Error("completion does not describe the restored include")
			}
			s.LearningKeys = f.learning
			managed, err := antispam.ManagedContent(s)
			if err != nil {
				t.Fatal(err)
			}
			managed[antispam.RoundcubeIncludePath] = prior
			if want != antispam.Generation(managed) {
				t.Error("the failed include check undid other requested changes")
			}
			// The hold removes the restored include on the next pass. Its
			// accurate record must avoid a redundant Exim or rspamd reload.
			f.reset()
			s.Roundcube = false
			wantOK(t, h.Apply(s))
			if f.count("systemctl reload") != 0 || f.count(BuildEximConf) != 0 {
				t.Error("removing the held include reloaded services")
			}
		})
	}
}

func TestRoundcubeRestoreSyncFailureCanRollBack(t *testing.T) {
	for _, prior := range []string{"", antispam.RenderRoundcube() + "// prior owned content\n"} {
		t.Run(map[bool]string{false: "absent", true: "owned"}[prior != ""], func(t *testing.T) {
			f := newFake(t)
			s := roundcubeApply(f)
			if prior != "" {
				writeTest(t, f.root+antispam.RoundcubeIncludePath, prior, 0o644)
			}
			before := f.state()
			f.roundcubeOverride = "INBOX.Trash"
			h := f.host()
			failed := false
			h.replace = func(p string, want, next fileState) error {
				if err := replaceFile(p, want, next); err != nil {
					return err
				}
				if !failed && p == f.root+antispam.RoundcubeIncludePath && next.content == prior {
					failed = true
					return errDurability
				}
				return nil
			}
			r := h.Apply(s)
			if !failed || r.OK || r.FailedStep != StepRoundcube || r.Rollback != antispam.RollbackVerified {
				t.Fatalf("result = %+v, failure injected=%t", r, failed)
			}
			if !maps.Equal(f.state(), before) {
				t.Fatal("rollback did not restore the prior files and record")
			}
		})
	}
}

// An absent file alone cannot prove a previous removal is durable. The
// retry must still reach its parent directory to sync the removed entry.
func TestRoundcubeRemovalRetryNeedsDirectory(t *testing.T) {
	p := t.TempDir() + "/missing/zz-csm-antispam.inc.php"
	if err := deleteFile(p); !errors.Is(err, errDurability) {
		t.Fatalf("missing directory gave %v, want a durability failure", err)
	}
}
