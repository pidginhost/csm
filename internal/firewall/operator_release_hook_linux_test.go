//go:build linux

package firewall

import (
	"errors"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
)

// Undoing an operator block releases the address through the conditional
// restore path. A failed undo or a restored block must keep spray history.
func TestOperatorReleaseHookOnUndoBlock(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prior   *BlockedEntry
		changed bool
		fail    bool
		want    bool
	}{
		{name: "remove block", want: true},
		{name: "expired prior", prior: &BlockedEntry{IP: "192.0.2.9", ExpiresAt: time.Unix(1, 0)}, want: true},
		{name: "restore block", prior: &BlockedEntry{IP: "192.0.2.9", Reason: "operator"}},
		{name: "changed block", changed: true},
		{name: "kernel failure", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, _ := nftConnReturningErrsThenOK(t)
			if tc.fail {
				conn = nftConnReturningErr(t, syscall.EPERM)
			}
			e, calls := releaseHookEngine(t, conn)
			entry := BlockedEntry{IP: "192.0.2.9", Reason: "operator", Source: SourceCLI, BlockedAt: time.Now()}
			if err := e.saveBlockedEntry(entry); err != nil {
				t.Fatal(err)
			}
			expected := entry
			if tc.changed {
				expected.Reason = "superseded"
			}
			err := e.RestoreBlockIfUnchanged("::ffff:192.0.2.9", &expected, tc.prior)
			switch {
			case tc.changed && !errors.Is(err, ErrBlockChanged):
				t.Fatalf("changed block: %v, want ErrBlockChanged", err)
			case tc.fail && !errors.Is(err, syscall.EPERM):
				t.Fatalf("kernel failure = %v, want EPERM", err)
			case !tc.changed && !tc.fail && err != nil:
				t.Fatal(err)
			}
			var want []string
			if tc.want {
				want = []string{entry.IP}
			}
			if !slices.Equal(*calls, want) {
				t.Fatalf("release hooks = %v, want %v", *calls, want)
			}
		})
	}
}

// releaseCall names one hook call: the address for an operator release,
// "unban <address>" for a self-service unban.
func releaseCall(ip string, kind ReleaseKind) string {
	if kind == ReleaseUnban {
		return "unban " + ip
	}
	return ip
}

// releaseHookEngine has IPv4 and IPv6 blocked and allowed sets on conn and
// records every hook call.
func releaseHookEngine(t *testing.T, conn *nftables.Conn) (*Engine, *[]string) {
	t.Helper()
	e := newTestEngine(t)
	e.conn = conn
	e.cfg.IPv6 = true
	e.setBlocked = namedIPv4Set("blocked_ips")
	e.setAllowed = namedIPv4Set("allowed_ips")
	e.setBlocked6 = namedIPv4Set("blocked_ips6")
	e.setBlocked6.KeyType = nftables.TypeIP6Addr
	e.setAllowed6 = namedIPv4Set("allowed_ips6")
	e.setAllowed6.KeyType = nftables.TypeIP6Addr
	calls := &[]string{}
	e.SetOperatorReleaseHook(func(ip string, kind ReleaseKind) { *calls = append(*calls, releaseCall(ip, kind)) })
	return e, calls
}

var releaseHookMethods = []struct {
	name string
	call func(*Engine, string) error
}{
	{"unblock", func(e *Engine, ip string) error { return e.UnblockIP(ip) }},
	{"undo-unblock", func(e *Engine, ip string) error { _, err := e.UnblockIPForUndo(ip); return err }},
	{"allow", func(e *Engine, ip string) error { return e.AllowIP(ip, "operator") }},
	{"temp allow", func(e *Engine, ip string) error { return e.TempAllowIP(ip, "operator", time.Hour) }},
}

// Each release reports the canonical address once, after the engine lock
// is released: the hook may read the engine and sees the address released.
func TestOperatorReleaseHookFires(t *testing.T) {
	for _, m := range releaseHookMethods {
		for _, tc := range []struct{ given, want string }{
			{"2001:DB8::5", "2001:db8::5"},
			{"::ffff:192.0.2.5", "192.0.2.5"},
		} {
			t.Run(m.name+"/"+tc.given, func(t *testing.T) {
				conn, _ := nftConnReturningErrsThenOK(t)
				e, calls := releaseHookEngine(t, conn)
				if err := e.saveBlockedEntry(BlockedEntry{IP: tc.want, Reason: "spray", BlockedAt: time.Now()}); err != nil {
					t.Fatal(err)
				}
				blockedInHook := true
				e.SetOperatorReleaseHook(func(ip string, kind ReleaseKind) {
					*calls = append(*calls, releaseCall(ip, kind))
					blockedInHook = e.IsBlocked(ip)
				})
				done := make(chan error, 1)
				go func() { done <- m.call(e, tc.given) }()
				select {
				case err := <-done:
					if err != nil {
						t.Fatalf("%s: %v", m.name, err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("release did not return: the hook ran under the engine lock")
				}
				if !slices.Equal(*calls, []string{tc.want}) {
					t.Fatalf("hook calls = %q, want [%s]", *calls, tc.want)
				}
				if blockedInHook {
					t.Fatal("hook ran before the address was released")
				}
			})
		}
	}
}

// Review focus 4: the block already expired, so state holds no row and the
// kernel no element. The unblock still succeeds and reports the address,
// so its spray marker can be cleared.
func TestOperatorReleaseHookFiresForExpiredBlock(t *testing.T) {
	for _, m := range releaseHookMethods[:2] {
		t.Run(m.name, func(t *testing.T) {
			e, calls := releaseHookEngine(t, nftConnReturningErr(t, syscall.ENOENT))
			if err := m.call(e, "192.0.2.9"); err != nil {
				t.Fatalf("%s of an expired block: %v", m.name, err)
			}
			if !slices.Equal(*calls, []string{"192.0.2.9"}) {
				t.Fatalf("hook calls = %q, want [192.0.2.9]", *calls)
			}
		})
	}
}

func TestOperatorReleaseHookFlushSignalsAll(t *testing.T) {
	conn, _ := nftConnReturningErrsThenOK(t)
	e, calls := releaseHookEngine(t, conn)
	if err := e.saveState(&FirewallState{Blocked: []BlockedEntry{{IP: "192.0.2.10"}, {IP: "2001:db8::10"}}}); err != nil {
		t.Fatal(err)
	}
	if err := e.FlushBlocked(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*calls, []string{""}) {
		t.Fatalf("hook calls = %q, want one call for every address", *calls)
	}
}

func TestOperatorReleaseHookSkipsFailedRelease(t *testing.T) {
	for _, m := range releaseHookMethods {
		t.Run(m.name+"/invalid", func(t *testing.T) {
			conn, _ := nftConnReturningErrsThenOK(t)
			e, calls := releaseHookEngine(t, conn)
			if err := m.call(e, "not-an-ip"); err == nil {
				t.Fatal("invalid address released")
			}
			if len(*calls) != 0 {
				t.Fatalf("hook calls = %q, want none", *calls)
			}
		})
		t.Run(m.name+"/nft failure", func(t *testing.T) {
			e, calls := releaseHookEngine(t, nftConnReturningErr(t, syscall.EPERM))
			if err := e.saveBlockedEntry(BlockedEntry{IP: "192.0.2.11", Reason: "spray", BlockedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if err := m.call(e, "192.0.2.11"); err == nil {
				t.Fatal("release succeeded with a failing kernel")
			}
			if len(*calls) != 0 {
				t.Fatalf("hook calls = %q, want none", *calls)
			}
		})
	}
	t.Run("flush/nft failure", func(t *testing.T) {
		e, calls := releaseHookEngine(t, nftConnReturningErr(t, syscall.EPERM))
		if err := e.saveState(&FirewallState{Blocked: []BlockedEntry{{IP: "192.0.2.12"}}}); err != nil {
			t.Fatal(err)
		}
		if err := e.FlushBlocked(); err == nil {
			t.Fatal("flush succeeded with a failing kernel")
		}
		if len(*calls) != 0 {
			t.Fatalf("hook calls = %q, want none", *calls)
		}
	})
}

// A self-service unban lifts the block like UnblockIP, including one that
// already expired, and tells the hook it was an unban so the address keeps
// its failure history. A failed unban reports nothing.
func TestUnbanReleaseHookReportsUnban(t *testing.T) {
	conn, _ := nftConnReturningErrsThenOK(t)
	e, calls := releaseHookEngine(t, conn)
	if err := e.saveBlockedEntry(BlockedEntry{IP: "2001:db8::5", Reason: "spray", BlockedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := e.UnbanIP("2001:DB8::5"); err != nil {
		t.Fatal(err)
	}
	if e.IsBlocked("2001:db8::5") || !slices.Equal(*calls, []string{"unban 2001:db8::5"}) {
		t.Fatalf("after unban: blocked %v, hook calls %q", e.IsBlocked("2001:db8::5"), *calls)
	}

	e, calls = releaseHookEngine(t, nftConnReturningErr(t, syscall.ENOENT))
	if err := e.UnbanIP("192.0.2.9"); err != nil || !slices.Equal(*calls, []string{"unban 192.0.2.9"}) {
		t.Fatalf("unban of an expired block = %v, hook calls %q", err, *calls)
	}

	e, calls = releaseHookEngine(t, nftConnReturningErr(t, syscall.EPERM))
	if err := e.saveBlockedEntry(BlockedEntry{IP: "192.0.2.11", Reason: "spray", BlockedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := e.UnbanIP("192.0.2.11"); err == nil {
		t.Fatal("unban succeeded with a failing kernel")
	}
	if err := e.UnbanIP("not-an-ip"); err == nil {
		t.Fatal("invalid address unbanned")
	}
	if len(*calls) != 0 {
		t.Fatalf("hook calls after failed unbans = %q, want none", *calls)
	}
}
