//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

var (
	newSetElemMsg = netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWSETELEM)
	delSetElemMsg = netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_DELSETELEM)
)

// sentElements decodes one transaction: the addresses it adds, with their
// timeouts, and those it deletes.
func sentElements(t *testing.T, req []netlink.Message) (map[string]time.Duration, []string) {
	t.Helper()
	adds := map[string]time.Duration{}
	var dels []string
	for _, msg := range req {
		switch msg.Header.Type {
		case newSetElemMsg:
			maps.Copy(adds, killElements(t, msg))
		case delSetElemMsg:
			msg.Header.Type = newSetElemMsg
			for ip := range killElements(t, msg) {
				dels = append(dels, ip)
			}
		}
	}
	sort.Strings(dels)
	return adds, dels
}

// modelKernel makes the fixture's kernel run each transaction as nf_tables
// does: all or nothing, where deleting a missing element rejects the whole
// transaction with ENOENT. before runs first with the transaction's
// number, as time passing between the snapshot and the send. It returns
// the transactions sent.
func (f *batchFixture) modelKernel(t *testing.T, before func(n int)) *[][]netlink.Message {
	t.Helper()
	var sent [][]netlink.Message
	f.reply = func(req []netlink.Message) ([]netlink.Message, error) {
		sent = append(sent, req)
		if before != nil {
			before(len(sent))
		}
		adds, dels := sentElements(t, req)
		for _, ip := range dels {
			if _, ok := f.live[ip]; !ok {
				return nltest.Error(int(syscall.ENOENT), req)
			}
		}
		for _, ip := range dels {
			delete(f.live, ip)
			delete(f.expires, ip)
		}
		for ip, ttl := range adds {
			f.live[ip] = ttl
			delete(f.expires, ip)
		}
		var acks []netlink.Message
		for _, msg := range req {
			if msg.Header.Flags&netlink.Acknowledge != 0 {
				acks = append(acks, netlink.Message{Header: netlink.Header{Length: 4, Type: netlink.Error, Sequence: msg.Header.Sequence, PID: msg.Header.PID}, Data: []byte{0, 0, 0, 0}})
			}
		}
		return acks, nil
	}
	return &sent
}

func victimEffects(results []BlockResult) string {
	var out []string
	for _, r := range results {
		out = append(out, string(r.Victim))
	}
	return strings.Join(out, " ")
}

// victimAt moves the fixture's victim to ip.
func (f *batchFixture) victimAt(t *testing.T, victim BlockVictim, ip string) BlockVictim {
	t.Helper()
	delete(f.live, victim.IP)
	victim.IP = ip
	writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: []BlockedEntry{
		{IP: victim.IP, Reason: "auto", Source: SourceAutoResponse, ExpiresAt: victim.ExpiresAt, ActionID: victim.Action},
		{IP: "203.0.113.61", Reason: "operator", ExpiresAt: f.at.Add(time.Hour)},
	}})
	f.live[victim.IP] = time.Hour
	return victim
}

// A member evicts its victim in its own transaction: one state write that
// keeps the victim's row, one transaction deleting the victim and adding
// the member, and a readback of both sets proving the member present and
// the victim gone. The row goes once the ledger has the outcome.
func TestApplyBlockBatchEvictsInTheSameTransaction(t *testing.T) {
	for _, ip := range []string{"203.0.113.60", "2001:db8::60"} {
		f, victim := newVictimFixture(t)
		victim = f.victimAt(t, victim, ip)
		writes := f.countWrites(t)
		sent := f.modelKernel(t, nil)
		results, err := f.e.ApplyBlockBatch([]BlockMember{f.evicting("act_evict", "203.0.113.21", victim)})
		if err != nil || effects(results) != "applied/" || victimEffects(results) != "removed" {
			t.Fatalf("%s: results %+v, %v", ip, results, err)
		}
		if len(*sent) != 1 {
			t.Fatalf("%s: %d transactions", ip, len(*sent))
		}
		adds, dels := sentElements(t, (*sent)[0])
		if len(adds) != 1 || adds["203.0.113.21"] != time.Hour || fmt.Sprint(dels) != "["+ip+"]" {
			t.Fatalf("%s: adds %v, deletes %v", ip, adds, dels)
		}
		if rows := f.storedRows(t); *writes != 1 || rows[victim.IP].ActionID != victim.Action || rows["203.0.113.21"].ActionID != "act_evict" {
			t.Fatalf("%s: %d writes, rows %v", ip, *writes, rows)
		}
		if got := strings.Join(f.audited(t), ","); got != "block 203.0.113.21,evict_temp "+ip {
			t.Fatalf("%s: audit %s", ip, got)
		}
	}
}

// A victim that no longer qualifies is never deleted: its member needs a
// free slot, and the result says the victim was spared.
func TestApplyBlockBatchSparesAVictimThatNoLongerQualifies(t *testing.T) {
	for limit, want := range map[int]string{2: "failed/set_full", 3: "applied/"} {
		f, victim := newVictimFixture(t)
		f.e.cfg.DenyTempIPLimit = limit
		sent := f.modelKernel(t, nil)
		victim.ExpiresAt = victim.ExpiresAt.Add(time.Second)
		results, err := f.e.ApplyBlockBatch([]BlockMember{f.evicting("act_evict", "203.0.113.21", victim)})
		if err != nil || effects(results) != want || victimEffects(results) != "spared" {
			t.Fatalf("limit %d: results %+v, %v", limit, results, err)
		}
		for _, req := range *sent {
			if _, dels := sentElements(t, req); len(dels) != 0 {
				t.Fatalf("limit %d: deleted %v", limit, dels)
			}
		}
		if _, live := f.live[victim.IP]; !live {
			t.Fatalf("limit %d: the victim was removed", limit)
		}
	}
}

// A rejected transaction deletes nothing: the victim is spared and the
// state restored.
func TestApplyBlockBatchRejectionSparesTheVictim(t *testing.T) {
	f, victim := newVictimFixture(t)
	f.reply = func(req []netlink.Message) ([]netlink.Message, error) { return nltest.Error(int(syscall.EINVAL), req) }
	results, err := f.e.ApplyBlockBatch([]BlockMember{f.evicting("act_evict", "203.0.113.21", victim)})
	if err != nil || effects(results) != "failed/" || victimEffects(results) != "spared" || !errors.Is(results[0].Err, ErrBlockBatchRejected) {
		t.Fatalf("results %+v, %v", results, err)
	}
	if rows := f.storedRows(t); len(rows) != 2 || rows[victim.IP].ActionID != victim.Action {
		t.Fatalf("rows %v, want the prior state", rows)
	}
}

// An uncertain send proves neither the member nor the victim's removal;
// the victim's row stays as it was, so a restart restores it.
func TestApplyBlockBatchUncertainSendLeavesTheRemovalUnproven(t *testing.T) {
	f, victim := newVictimFixture(t)
	f.reply = func([]netlink.Message) ([]netlink.Message, error) { return nil, os.ErrDeadlineExceeded }
	results, err := f.e.ApplyBlockBatch([]BlockMember{f.evicting("act_evict", "203.0.113.21", victim)})
	if err != nil || effects(results) != "unknown/" || victimEffects(results) != "unproven" {
		t.Fatalf("results %+v, %v", results, err)
	}
	rows := f.storedRows(t)
	if len(rows) != 3 || rows[victim.IP].ActionID != victim.Action || rows[victim.IP].Unverified || !rows["203.0.113.21"].Unverified {
		t.Fatalf("rows %+v, want only the unknown member marked", rows)
	}
}

// Absence is proven only from a set the readback read: a victim in a
// family whose dump failed stays unproven, and its member is unknown
// though its own add was read back.
func TestApplyBlockBatchUnreadVictimFamilyIsUnproven(t *testing.T) {
	f, victim := newVictimFixture(t)
	victim = f.victimAt(t, victim, "2001:db8::60")
	sent := f.modelKernel(t, nil)
	dump := f.e.liveBlockedDump
	f.e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
		if len(*sent) > 0 && set == f.e.setBlocked6 {
			return nil, errors.New("IPv6 dump unavailable")
		}
		return dump(set)
	}
	results, err := f.e.ApplyBlockBatch([]BlockMember{f.evicting("act_evict", "203.0.113.21", victim)})
	if err != nil || effects(results) != "unknown/" || victimEffects(results) != "unproven" {
		t.Fatalf("results %+v, %v", results, err)
	}
	if _, dels := sentElements(t, (*sent)[0]); fmt.Sprint(dels) != "[2001:db8::60]" {
		t.Fatalf("deletes %v", dels)
	}
	if rows := f.storedRows(t); !rows["203.0.113.21"].Unverified || rows[victim.IP].Unverified {
		t.Fatalf("rows %v, want only the member marked unverified", rows)
	}
	if f.audited(t) != nil {
		t.Fatalf("audit %v; an unknown member and an unproven removal are not audited", f.audited(t))
	}
}

// A victim removed from the kernel between the snapshot and the send makes
// the kernel reject the whole transaction (ENOENT). The batch fails as any
// rejection does: nothing applies, the state is restored and the victim is
// spared; the owner retries with new charged attempts.
func TestApplyBlockBatchVanishedVictimRejectsTheBatch(t *testing.T) {
	f, victim := newVictimFixture(t)
	f.e.cfg.DenyTempIPLimit = 3
	sent := f.modelKernel(t, func(int) { delete(f.live, victim.IP) })
	results, err := f.e.ApplyBlockBatch([]BlockMember{
		f.evicting("act_evict", "203.0.113.21", victim),
		f.member("act_free", "203.0.113.20"),
	})
	if err != nil || effects(results) != "failed/ failed/" || victimEffects(results) != "spared " {
		t.Fatalf("results %+v, %v", results, err)
	}
	if !errors.Is(results[0].Err, ErrBlockBatchRejected) || !errors.Is(results[0].Err, syscall.ENOENT) {
		t.Fatalf("error %v, want a kernel rejection", results[0].Err)
	}
	if len(*sent) != 1 {
		t.Fatalf("%d transactions, want one", len(*sent))
	}
	if rows := f.storedRows(t); len(rows) != 2 || rows[victim.IP].ActionID != victim.Action {
		t.Fatalf("rows %v, want the prior state", rows)
	}
	if _, live := f.live["203.0.113.20"]; live {
		t.Fatal("a rejected transaction added a member")
	}
}

// A member that expires before the send takes its victim's removal with
// it: nothing is deleted for a block that never runs.
func TestApplyBlockBatchExpiredMemberSparesItsVictim(t *testing.T) {
	f, victim := newVictimFixture(t)
	f.e.cfg.DenyTempIPLimit = 3
	sent := f.modelKernel(t, nil)
	short := f.evicting("act_short", "203.0.113.21", victim)
	short.ExpiresAt = f.at.Add(time.Second)
	long := f.member("act_long", "203.0.113.20")
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })
	writeFirewallStateJSON = func(path string, mode os.FileMode, v any) error {
		err := prev(path, mode, v)
		f.at = f.at.Add(2 * time.Second)
		return err
	}
	results, err := f.e.ApplyBlockBatch([]BlockMember{short, long})
	if err != nil || effects(results) != "failed/expired applied/" || victimEffects(results) != "spared " {
		t.Fatalf("results %+v, %v", results, err)
	}
	if _, dels := sentElements(t, (*sent)[0]); len(*sent) != 1 || len(dels) != 0 {
		t.Fatalf("%d transactions, deletes %v", len(*sent), dels)
	}
	if _, live := f.live[victim.IP]; !live {
		t.Fatal("the victim was removed")
	}
}

// A victim with no more than a batch's minimum lifetime left at the send
// could expire before the kernel runs the transaction, which would then
// reject it whole with ENOENT and fail every member. Its member fails
// set_full alone instead: nothing is deleted and the other members apply.
// A millisecond more and the victim is removed.
func TestApplyBlockBatchSparesAVictimAboutToExpire(t *testing.T) {
	for _, tc := range []struct {
		left             time.Duration
		effects, victims string
		dels             int
	}{
		{blockBatchMinLifetime, "failed/set_full applied/", "spared ", 0},
		{blockBatchMinLifetime + time.Millisecond, "applied/ applied/", "removed ", 1},
	} {
		t.Run(tc.left.String(), func(t *testing.T) {
			f, victim := newVictimFixture(t)
			f.e.cfg.DenyTempIPLimit = 3
			sent := f.modelKernel(t, nil)
			evict := f.evicting("act_evict", "203.0.113.21", victim)
			free := f.member("act_free", "203.0.113.20")
			evict.ExpiresAt, free.ExpiresAt = f.at.Add(2*time.Hour), f.at.Add(2*time.Hour)
			prev := writeFirewallStateJSON
			t.Cleanup(func() { writeFirewallStateJSON = prev })
			writeFirewallStateJSON = func(path string, mode os.FileMode, v any) error {
				err := prev(path, mode, v)
				f.at = victim.ExpiresAt.Add(-tc.left)
				return err
			}
			results, err := f.e.ApplyBlockBatch([]BlockMember{evict, free})
			if err != nil || effects(results) != tc.effects || victimEffects(results) != tc.victims {
				t.Fatalf("results %+v, %v", results, err)
			}
			if adds, dels := sentElements(t, (*sent)[0]); len(*sent) != 1 || len(dels) != tc.dels || adds[free.IP] == 0 {
				t.Fatalf("%d transactions, adds %v, deletes %v", len(*sent), adds, dels)
			}
			if _, live := f.live[victim.IP]; live != (tc.dels == 0) {
				t.Fatalf("victim live %t after %d deletes", live, tc.dels)
			}
		})
	}
}

// UnreadEvictionVictimForTest fails only the victim family's readback;
// its initial snapshot succeeds. The external crash harness uses the real
// unknown-marking path while the other family still proves the member.
func UnreadEvictionVictimForTest(e *Engine, ip string) {
	set := e.setBlocked
	if net.ParseIP(ip).To4() == nil {
		set = e.setBlocked6
	}
	dump, reads := e.liveBlockedDump, 0
	e.liveBlockedDump = func(s *nftables.Set) ([]nftables.SetElement, error) {
		if s == set {
			reads++
			if reads > 1 {
				return nil, errors.New("victim family readback unavailable")
			}
		}
		return dump(s)
	}
}
