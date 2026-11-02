package hostfacts

import (
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/dovecot"
)

func TestSkippedDovecotMailboxStillSharesServiceUID(t *testing.T) {
	for _, conditional := range []bool{false, true} {
		c, f := postfixCollector(t, postfixPasswd)
		f.ControllerHost.RspamdUID = 979
		c.dovecot = dovecot.Dovecot{Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			switch name {
			case "dovecot":
				return []byte("2.3.21"), nil
			case "doveconf":
				loc := "maildir:~/Maildir"
				if conditional {
					loc += ":INDEX=%{if;%d;eq;example.com;/a;/b}"
				}
				return []byte("mail_location = " + loc + "\nnamespace inbox {\n mailbox Junk {\n special_use = \\Junk\n }\n}\n"), nil
			case "doveadm":
				if len(args) == 2 {
					return []byte("a@example.com\n"), nil
				}
				if conditional {
					if strings.Contains(args[2], "{if") {
						t.Fatal("conditional location was passed to the identity lookup")
					}
					return []byte("a@example.com\t979\t974\t/srv/vmail/a\t\tzlib\t\ta@example.com\n"), nil
				}
				return []byte("a@example.com\t979\t974\t/srv/vmail/a\t\tzlib\tmaildir:~/Maildir\ta@example.com\n"), nil
			}
			t.Fatalf("unexpected command %s %q", name, args)
			return nil, nil
		}}.Snapshot
		c.learningFacts(context.Background(), antispam.Settings{Learning: true}, &f)
		if f.Dovecot.Err != nil || !slices.Equal(f.Dovecot.UIDs, []int{979}) || !f.RspamdUIDShared {
			t.Fatalf("conditional=%v: skipped mailbox lost its service uid: Dovecot %+v, shared %v", conditional, f.Dovecot, f.RspamdUIDShared)
		}
	}
}

func TestPostfixRedisAccountOutageIsTemporary(t *testing.T) {
	for _, failedRead := range []bool{false, true} {
		uid := os.Getuid()
		if uid == 0 {
			uid = 990
		}
		passwd := strings.Replace(postfixPasswd, "redis:x:990:", "redis:x:"+strconv.Itoa(uid)+":", 1)
		c, f := postfixCollector(t, passwd)
		socket := serve(t, t.TempDir(), pong)
		if os.Getuid() == 0 {
			if err := os.Chown(socket, uid, 990); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(socket, 0o600); err != nil {
			t.Fatal(err)
		}
		if failedRead {
			c.readPasswd = func() ([]byte, error) { return nil, os.ErrPermission }
		} else {
			lookup := c.uid
			c.uid = func(name string) (int, error) {
				if name == "alice" {
					return -1, errors.New("NSS unavailable")
				}
				return lookup(name)
			}
		}
		probed := false
		c.redisProbe = func(context.Context, string, antispam.Secret, int) antispam.RedisFacts {
			probed = true
			return antispam.RedisFacts{}
		}
		c.learningRedis(context.Background(), socket, &f)
		if f.Redis.Err == nil || f.Redis.Unprotected || probed {
			t.Fatalf("failedRead=%v: account outage classified as exposure or probed: err %v, unprotected %v, probed %v", failedRead, f.Redis.Err, f.Redis.Unprotected, probed)
		}
		// An already installed endpoint survives an outage under the worker lock.
		f.Targets = []antispam.TargetFacts{{Target: antispam.Target{Path: antispam.LearningWorkerPath, Kind: antispam.TargetRspamd}, Content: antispam.ManagedHeader + "\nservers = \"" + socket + "\";\n"}}
		if err := antispam.CheckLearningRedis(dedicatedSettings(socket), f); err != nil {
			t.Fatalf("installed endpoint rejected on account outage: %v", err)
		}
	}
}

func TestLearningRedisRechecksDovecotUnderWorkerLock(t *testing.T) {
	c, f := postfixCollector(t, postfixPasswd)
	calls := 0
	c.dovecot = snapshotOf(dovecot.Snapshot{Complete: true, Skips: []dovecot.Skip{{User: "a@example.com", Reason: dovecot.SkipPluginZlib, UID: 990}}}, nil, &calls)
	c.learningRedis(context.Background(), "/run/redis-csm/redis.sock", &f)
	if calls != 1 || !f.AccountNames["redis"] || !slices.Equal(f.Dovecot.UIDs, []int{990}) {
		t.Fatalf("worker Redis recheck missed the current mail UID: calls %d, names %v, Dovecot %+v", calls, f.AccountNames, f.Dovecot)
	}
}
