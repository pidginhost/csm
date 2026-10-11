//go:build linux

package firewall

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
)

func (f *batchFixture) countWrites(t *testing.T) *int {
	t.Helper()
	writes := 0
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })
	writeFirewallStateJSON = func(path string, perm os.FileMode, v any) error {
		writes++
		return prev(path, perm, v)
	}
	return &writes
}

// kernelHolds makes an acknowledged batch leave these addresses in the
// kernel with the time left given, all with a one-hour timeout.
func (f *batchFixture) kernelHolds(left map[string]time.Duration) {
	f.onFlush = func() {
		for ip, d := range left {
			f.live[ip] = time.Hour
			f.expires[ip] = d
		}
	}
}

func (f *batchFixture) storedRows(t *testing.T) map[string]BlockedEntry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.e.statePath, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state FirewallState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	rows := map[string]BlockedEntry{}
	for _, row := range state.Blocked {
		rows[row.IP] = row
	}
	return rows
}

func (f *batchFixture) audited(t *testing.T) []string {
	t.Helper()
	file, err := os.Open(filepath.Join(f.e.statePath, "audit.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	var out []string
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		var row map[string]any
		if err := json.Unmarshal(scan.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		out = append(out, row["action"].(string)+" "+row["ip"].(string))
	}
	sort.Strings(out)
	return out
}

func effects(results []BlockResult) string {
	var out []string
	for _, r := range results {
		out = append(out, string(r.Effect)+"/"+string(r.Refusal))
	}
	return strings.Join(out, " ")
}

func TestApplyBlockBatchPersistsTheAuthorizedExpiryInstant(t *testing.T) {
	for _, offset := range []int{24 * 60 * 60, -24 * 60 * 60, 59, -59} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			writes := f.countWrites(t)
			f.kernelHolds(map[string]time.Duration{"203.0.113.20": time.Hour, "2001:db8::20": time.Hour})
			zoned := f.member("act_v4", "203.0.113.20")
			zoned.ExpiresAt = zoned.ExpiresAt.In(time.FixedZone("example", offset))
			good := f.member("act_v6", "2001:db8::20")
			results, err := f.e.ApplyBlockBatch([]BlockMember{zoned, good})
			if err != nil || effects(results) != "applied/ applied/" || *writes != 1 || f.sends != 1 {
				t.Fatalf("effects %s, error %v, writes %d, sends %d; equivalent expiry must not poison a neighbor", effects(results), err, *writes, f.sends)
			}
			rows := f.storedRows(t)
			for _, member := range []BlockMember{zoned, good} {
				row, ok := rows[member.IP]
				if !ok || !row.ExpiresAt.Equal(member.ExpiresAt) {
					t.Fatalf("stored expiry %v, want authorized instant %v", row.ExpiresAt, member.ExpiresAt)
				}
				timeout, ok := blockTimeout(row.ExpiresAt, f.at)
				if !ok || timeout != time.Hour {
					t.Fatalf("restored timeout %v, %v; want exactly one hour", timeout, ok)
				}
			}
		})
	}
}

func TestApplyBlockBatchAppliesVerifiedMembers(t *testing.T) {
	f := newBatchFixture(t, FirewallState{Blocked: []BlockedEntry{{IP: "203.0.113.40", Reason: "operator"}}})
	writes := f.countWrites(t)
	f.kernelHolds(map[string]time.Duration{"203.0.113.20": time.Hour - 5*time.Millisecond, "2001:db8::20": time.Hour})
	members := []BlockMember{
		f.member("act_v4", "203.0.113.20"),
		f.member("act bad", "203.0.113.21"),
		f.member("act_v6", "2001:db8::20"),
		f.member("act_row", "203.0.113.40"),
	}

	results, err := f.e.ApplyBlockBatch(members)
	if err != nil {
		t.Fatal(err)
	}
	if got := effects(results); got != "applied/ failed/invalid applied/ failed/existing_effect" {
		t.Fatalf("effects = %s", got)
	}
	if *writes != 1 || f.sends != 1 {
		t.Fatalf("%d state writes and %d kernel batches, want one of each", *writes, f.sends)
	}
	rows := f.storedRows(t)
	for _, m := range []BlockMember{members[0], members[2]} {
		row := rows[m.IP]
		if row.ActionID != m.Action || row.Unverified || row.Source != SourceAutoResponse || !row.ExpiresAt.Equal(m.ExpiresAt) || row.Reason != m.Reason {
			t.Fatalf("row %s = %+v", m.IP, row)
		}
	}
	if _, ok := rows["203.0.113.21"]; ok {
		t.Fatal("a refused member wrote a row")
	}
	if got := strings.Join(f.audited(t), ","); got != "block 2001:db8::20,block 203.0.113.20" {
		t.Fatalf("audit = %s", got)
	}
	if !f.e.IsBlocked("203.0.113.20") || !f.e.IsBlocked("2001:db8::20") {
		t.Fatal("applied members are not reported as blocked")
	}
}

func TestApplyBlockBatchReadbackDecidesEachMember(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	writes := f.countWrites(t)
	f.onFlush = func() {
		f.live["203.0.113.20"], f.expires["203.0.113.20"] = time.Hour, time.Hour-5*time.Millisecond
		f.live["203.0.113.22"] = 2 * time.Hour // an older, longer block
		f.live["203.0.113.23"], f.expires["203.0.113.23"] = time.Hour, 10*time.Minute
		f.live["203.0.113.24"] = 0 // a permanent block
		f.live["203.0.113.25"], f.expires["203.0.113.25"] = time.Hour, time.Hour+time.Millisecond
		f.live["203.0.113.26"] = 0 // permanent where a short block was sent
		// An older two-hour block whose time left happens to match.
		f.live["203.0.113.27"], f.expires["203.0.113.27"] = 2*time.Hour, time.Hour-5*time.Millisecond
	}
	var members []BlockMember
	for _, ip := range []string{"203.0.113.20", "203.0.113.21", "203.0.113.22", "203.0.113.23", "203.0.113.24", "203.0.113.25", "203.0.113.27"} {
		members = append(members, f.member("act_"+strings.ReplaceAll(ip, ".", "_"), ip))
	}
	short := f.member("act_short", "203.0.113.26")
	short.ExpiresAt = f.at.Add(500 * time.Millisecond)
	members = append(members, short)

	results, err := f.e.ApplyBlockBatch(members)
	if err != nil {
		t.Fatal(err)
	}
	if got := effects(results); got != "applied/ unknown/ unknown/ unknown/ unknown/ unknown/ unknown/ unknown/" {
		t.Fatalf("effects = %s", got)
	}
	if *writes != 2 {
		t.Fatalf("%d state writes, want the intent and the unknown flags", *writes)
	}
	rows := f.storedRows(t)
	for ip, row := range rows {
		if row.Unverified != (ip != "203.0.113.20") {
			t.Fatalf("row %s unverified = %t", ip, row.Unverified)
		}
	}
	if len(rows) != len(members) {
		t.Fatalf("stored %d rows, want %d", len(rows), len(members))
	}
	if f.e.IsBlocked("203.0.113.21") {
		t.Fatal("an unknown member is reported as blocked")
	}
	if got := strings.Join(f.audited(t), ","); got != "block 203.0.113.20" {
		t.Fatalf("audit = %s", got)
	}
}

func TestApplyBlockBatchRejectionFailsEveryMemberAndRestoresState(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EINVAL, syscall.ENOENT, syscall.EPERM, syscall.EMSGSIZE, syscall.ERANGE} {
		t.Run(errno.Error(), func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{Blocked: []BlockedEntry{{IP: "203.0.113.40", Reason: "operator"}}})
			writes := f.countWrites(t)
			f.reply = func(req []netlink.Message) ([]netlink.Message, error) { return nltest.Error(int(errno), req) }

			results, err := f.e.ApplyBlockBatch([]BlockMember{f.member("act_v4", "203.0.113.20"), f.member("act_v6", "2001:db8::20")})
			if err != nil {
				t.Fatal(err)
			}
			if got := effects(results); got != "failed/ failed/" {
				t.Fatalf("effects = %s", got)
			}
			for _, r := range results {
				if !errors.Is(r.Err, errno) {
					t.Fatalf("result error = %v, want %v", r.Err, errno)
				}
			}
			rows := f.storedRows(t)
			if len(rows) != 1 || *writes != 2 {
				t.Fatalf("rows %v after %d writes, want the prior state restored", rows, *writes)
			}
			if f.audited(t) != nil {
				t.Fatal("a rejected batch was audited")
			}
		})
	}
}

func TestApplyBlockBatchUncertainKernelReplyIsUnknown(t *testing.T) {
	for name, cause := range map[string]error{
		"deadline": os.ErrDeadlineExceeded,
		"eintr":    syscall.EINTR,
		"enobufs":  syscall.ENOBUFS,
		"eagain":   syscall.EAGAIN,
		"other":    errors.New("message mismatch"),
	} {
		t.Run(name, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			writes := f.countWrites(t)
			f.reply = func([]netlink.Message) ([]netlink.Message, error) { return nil, cause }

			results, err := f.e.ApplyBlockBatch([]BlockMember{f.member("act_v4", "203.0.113.20"), f.member("act_v6", "2001:db8::20")})
			if err != nil {
				t.Fatal(err)
			}
			if got := effects(results); got != "unknown/ unknown/" {
				t.Fatalf("effects = %s", got)
			}
			rows := f.storedRows(t)
			if len(rows) != 2 || !rows["203.0.113.20"].Unverified || !rows["2001:db8::20"].Unverified || *writes != 2 {
				t.Fatalf("rows %+v after %d writes, want both kept unverified", rows, *writes)
			}
		})
	}
}

func TestApplyBlockBatchUnreadableKernelAfterAckIsUnknown(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.onFlush = func() { f.err = errors.New("dump failed") }

	results, err := f.e.ApplyBlockBatch([]BlockMember{f.member("act_v4", "203.0.113.20")})
	if err != nil {
		t.Fatal(err)
	}
	if got := effects(results); got != "unknown/" || results[0].Err == nil {
		t.Fatalf("effects = %s, error %v", got, results[0].Err)
	}
	if !f.storedRows(t)["203.0.113.20"].Unverified {
		t.Fatal("an unverifiable member is not flagged")
	}
}

func TestApplyBlockBatchStateWriteFailureDispatchesNothing(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })
	writeFirewallStateJSON = func(string, os.FileMode, any) error { return errors.New("disk full") }

	results, err := f.e.ApplyBlockBatch([]BlockMember{f.member("act_v4", "203.0.113.20")})
	if err != nil {
		t.Fatal(err)
	}
	if got := effects(results); got != "failed/" || results[0].Err == nil || f.sends != 0 {
		t.Fatalf("effects = %s, error %v, %d kernel batches", got, results[0].Err, f.sends)
	}
}

func TestApplyBlockBatchRevalidatesAgainstTheCurrentState(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	members := []BlockMember{f.member("act_v4", "203.0.113.20")}
	if checked, err := f.e.CheckBlockBatch(members); err != nil || checked[0] != "" {
		t.Fatalf("check = %q, %v", checked, err)
	}
	f.live["203.0.113.20"] = time.Hour // blocked by someone else since the check
	writes := f.countWrites(t)

	results, err := f.e.ApplyBlockBatch(members)
	if err != nil {
		t.Fatal(err)
	}
	if got := effects(results); got != "failed/existing_effect" || *writes != 0 || f.sends != 0 {
		t.Fatalf("effects = %s after %d writes and %d kernel batches", got, *writes, f.sends)
	}
}

func TestApplyBlockBatchRefusesTheWholeCall(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	if _, err := f.e.ApplyBlockBatch(nil); err == nil {
		t.Fatal("an empty batch ran")
	}
	tooMany := make([]BlockMember, MaxBlockBatchMembers+1)
	for i := range tooMany {
		tooMany[i] = f.member("act_x", "203.0.113.20")
	}
	if _, err := f.e.ApplyBlockBatch(tooMany); err == nil {
		t.Fatal("a batch over the member bound ran")
	}
	f.err = errors.New("dump failed")
	if _, err := f.e.ApplyBlockBatch(tooMany[:1]); err == nil {
		t.Fatal("a batch ran without a kernel snapshot")
	}
	durable := newBatchFixture(t, FirewallState{})
	durable.e.lifecycle = &Lifecycle{}
	if _, err := durable.e.ApplyBlockBatch(tooMany[:1]); err == nil {
		t.Fatal("a batch ran against durable state")
	}
	if f.sends != 0 || durable.sends != 0 {
		t.Fatal("a refused call reached the kernel")
	}
}

func TestApplyBlockBatchQueueFailureSendsNothing(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.e.setBlocked6.Anonymous = true // the library refuses to queue into it
	writes := f.countWrites(t)

	results, err := f.e.ApplyBlockBatch([]BlockMember{f.member("act_v4", "203.0.113.20"), f.member("act_v6", "2001:db8::20")})
	if err != nil {
		t.Fatal(err)
	}
	if got := effects(results); got != "failed/ failed/" || results[0].Err == nil || f.sends != 0 {
		t.Fatalf("effects = %s, error %v, %d kernel batches", got, results[0].Err, f.sends)
	}
	if rows := f.storedRows(t); len(rows) != 0 || *writes != 2 {
		t.Fatalf("rows %v after %d writes, want the prior state restored", rows, *writes)
	}
}

type batchTimeoutError struct{ cause error }

func (e batchTimeoutError) Error() string { return "batch deadline" }
func (e batchTimeoutError) Unwrap() error { return e.cause }
func (e batchTimeoutError) Timeout() bool { return true }

func TestApplyBlockBatchErrorClassesPreserveProvenance(t *testing.T) {
	rejected := &netlink.OpError{Op: "receive", Err: syscall.EINVAL, Sequence: 1}
	for _, tc := range []struct {
		name     string
		cause    error
		rejected bool
	}{
		{"unwrapped_permission", syscall.EPERM, true},
		{"wrapped_permission", fmt.Errorf("reply: %w", syscall.EPERM), true},
		{"kernel_reply", rejected, true},
		{"rejection_then_deadline", errors.Join(rejected, os.ErrDeadlineExceeded), true},
		{"deadline_then_rejection", errors.Join(os.ErrDeadlineExceeded, rejected), true},
		{"local_receive", &netlink.OpError{Op: "receive", Err: os.NewSyscallError("recvmsg", syscall.ENOMEM)}, false},
		{"local_receive_and_deadline", errors.Join(&netlink.OpError{Op: "receive", Err: os.NewSyscallError("recvmsg", syscall.EBADF)}, os.ErrDeadlineExceeded), false},
		{"wrapped_deadline_errno", batchTimeoutError{cause: syscall.EINVAL}, false},
		{"atomic_send", &netlink.OpError{Op: "send-messages", Err: os.NewSyscallError("sendmsg", syscall.EMSGSIZE)}, true},
		{"interrupted", syscall.EINTR, false},
		{"again", syscall.EAGAIN, false},
		{"buffer", syscall.ENOBUFS, false},
		{"timeout", syscall.ETIMEDOUT, false},
		{"no_errno", errors.New("lost reply"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := kernelRejected(tc.cause); got != tc.rejected {
				t.Fatalf("rejected(%v) = %t, want %t", tc.cause, got, tc.rejected)
			}
		})
	}
}

func TestApplyBlockBatchReadbackRequiresTimeoutIdentity(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		timeout, expires, elapsed time.Duration
		want                      bool
	}{
		{"tick_truncation", time.Hour - 5*time.Millisecond, time.Hour - 10*time.Millisecond, time.Second, true},
		{"slow_exact", time.Hour, time.Hour - 2*time.Minute, 2 * time.Minute, true},
		{"longer", time.Hour + time.Millisecond, time.Hour + time.Millisecond, time.Second, false},
		{"slow_shorter", 59 * time.Minute, 58 * time.Minute, 2 * time.Minute, false},
		{"no_timeout", 0, time.Hour, time.Second, false},
		{"expires_above_timeout", time.Hour - time.Millisecond, time.Hour, time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := readbackMatches(nftables.SetElement{Timeout: tc.timeout, Expires: tc.expires}, time.Hour, tc.elapsed+blockReadbackSlack); got != tc.want {
				t.Fatalf("timeout %v, expires %v, elapsed %v: applied %t, want %t", tc.timeout, tc.expires, tc.elapsed, got, tc.want)
			}
		})
	}
}

func TestApplyBlockBatchUnknownMarkWriteFailureStaysSuppressed(t *testing.T) {
	for _, visible := range []bool{false, true} {
		t.Run(fmt.Sprint(visible), func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			f.onFlush = func() { f.err = errors.New("dump failed") }
			prev := writeFirewallStateJSON
			t.Cleanup(func() { writeFirewallStateJSON = prev })
			writes := 0
			writeFirewallStateJSON = func(path string, mode os.FileMode, v any) error {
				writes++
				if writes == 2 {
					if visible {
						if err := prev(path, mode, v); err != nil {
							return err
						}
					}
					return errors.New("state durability failed")
				}
				return prev(path, mode, v)
			}
			members := []BlockMember{f.member("act_v4", "203.0.113.20")}
			got, err := f.e.ApplyBlockBatch(members)
			if err != nil || effects(got) != "unknown/" || !errors.Is(got[0].Err, ErrBlockBatchState) {
				t.Fatalf("results %+v, error %v", got, err)
			}
			f.err = nil
			for i := 0; i < 2; i++ {
				if f.e.IsBlocked(members[0].IP) || f.e.BlockedCount() != 0 || f.e.RuleCounts().Blocked != 0 || f.e.Status()["blocked"] != 0 {
					t.Fatal("unknown member reported after failed marking")
				}
				f.e.mu.Lock()
				initial := f.e.computeInitialBlockStateLocked()
				f.e.clearStateCacheLocked()
				f.e.mu.Unlock()
				if len(initial.blocked4) != 0 {
					t.Fatal("unknown member re-seeded after failed marking")
				}
			}
			if _, checkErr := f.e.CheckBlockBatch([]BlockMember{f.member("act_new", "203.0.113.21")}); !errors.Is(checkErr, ErrBlockBatchState) {
				t.Fatalf("state hold missing: %v", checkErr)
			}
			if _, applyErr := f.e.ApplyBlockBatch([]BlockMember{f.member("act_new", "203.0.113.21")}); !errors.Is(applyErr, ErrBlockBatchState) || f.sends != 1 {
				t.Fatalf("state hold bypassed: %v, sends %d", applyErr, f.sends)
			}
			f.e.mu.Lock()
			next := f.e.loadStateFile()
			upsertBlockedEntryInState(&next, BlockedEntry{IP: "203.0.113.40", Reason: "operator"})
			err = f.e.saveState(&next)
			f.e.mu.Unlock()
			if err != nil || !f.storedRows(t)[members[0].IP].Unverified || f.e.IsBlocked(members[0].IP) {
				t.Fatalf("unrelated save lost suppression: %v", err)
			}
		})
	}
}

func TestApplyBlockBatchFailedStateRestoreStaysSuppressed(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.reply = func(req []netlink.Message) ([]netlink.Message, error) { return nltest.Error(int(syscall.EINVAL), req) }
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })
	writes := 0
	writeFirewallStateJSON = func(path string, mode os.FileMode, v any) error {
		writes++
		if writes == 2 {
			return errors.New("restore failed")
		}
		return prev(path, mode, v)
	}
	got, err := f.e.ApplyBlockBatch([]BlockMember{f.member("act_v4", "203.0.113.20")})
	if err != nil || effects(got) != "failed/" || !errors.Is(got[0].Err, syscall.EINVAL) || !errors.Is(got[0].Err, ErrBlockBatchState) {
		t.Fatalf("results %+v, %v", got, err)
	}
	if f.e.IsBlocked("203.0.113.20") || f.e.BlockedCount() != 0 {
		t.Fatal("failed row reported after restore failure")
	}
	f.e.mu.Lock()
	initial := f.e.computeInitialBlockStateLocked()
	f.e.clearStateCacheLocked()
	f.e.mu.Unlock()
	if len(initial.blocked4) != 0 || f.e.IsBlocked("203.0.113.20") {
		t.Fatal("failed row restored or re-reported")
	}
}

func TestApplyBlockBatchIntentDurabilityAndRestoreFailureSendsNothing(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })
	writes := 0
	writeFirewallStateJSON = func(path string, mode os.FileMode, v any) error {
		writes++
		if writes == 1 {
			if err := prev(path, mode, v); err != nil {
				return err
			}
		}
		return errors.New("durability failed")
	}
	got, err := f.e.ApplyBlockBatch([]BlockMember{f.member("act_v4", "203.0.113.20")})
	if err != nil || effects(got) != "failed/" || !errors.Is(got[0].Err, ErrBlockBatchState) || f.sends != 0 || f.e.IsBlocked("203.0.113.20") {
		t.Fatalf("results %+v, error %v, sends %d", got, err, f.sends)
	}
}

func TestApplyBlockBatchDoesNotMatchMappedReadback(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
		if f.sends == 0 || set == f.e.setBlocked {
			return nil, nil
		}
		return []nftables.SetElement{
			{Key: net.ParseIP("203.0.113.20").To16(), Timeout: time.Hour, Expires: time.Hour},
			{Key: net.ParseIP("2001:db8::20").To16(), Timeout: time.Hour, Expires: time.Hour},
		}, nil
	}
	got, err := f.e.ApplyBlockBatch([]BlockMember{f.member("act_v4", "203.0.113.20"), f.member("act_v6", "2001:db8::20")})
	if err != nil || effects(got) != "unknown/ applied/" {
		t.Fatalf("results %+v, %v; mapped IPv6 key cannot prove IPv4", got, err)
	}
}

func TestApplyBlockBatchRetainsSuccessfulFamilyReadback(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	dump := f.e.liveBlockedDump
	f.kernelHolds(map[string]time.Duration{"203.0.113.20": time.Hour})
	f.e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
		if f.sends > 0 && set == f.e.setBlocked6 {
			return nil, errors.New("IPv6 dump unavailable")
		}
		return dump(set)
	}
	got, err := f.e.ApplyBlockBatch([]BlockMember{f.member("act_v4", "203.0.113.20"), f.member("act_v6", "2001:db8::20")})
	if err != nil || effects(got) != "applied/ unknown/" || got[1].Err == nil {
		t.Fatalf("results %+v, %v", got, err)
	}
}

func TestApplyBlockBatchPreSendFailureWithoutErrnoFailsEveryMember(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.e.conn = nil
	got, err := f.e.ApplyBlockBatch([]BlockMember{f.member("act_v4", "203.0.113.20"), f.member("act_v6", "2001:db8::20")})
	if err != nil || effects(got) != "failed/ failed/" || f.sends != 0 || len(f.storedRows(t)) != 0 {
		t.Fatalf("results %+v, %v, sends %d", got, err, f.sends)
	}
}

func TestApplyBlockBatchSocketOptionFailsBeforeQueueing(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	cause := errors.New("socket option failed")
	calls := 0
	conn, err := newBlockBatchConn(f.e, nftables.WithSockOptions(func(c *netlink.Conn) error { calls++; _ = c.Close(); return cause }))
	if conn != nil {
		_ = conn.CloseLasting()
	}
	if !errors.Is(err, cause) || calls != 1 || f.sends != 0 {
		t.Fatalf("construction %v, option calls %d, sends %d", err, calls, f.sends)
	}
}

func TestApplyBlockBatchRefreshesTimeoutAfterStateWrite(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	short := f.member("act_short", "203.0.113.21")
	short.ExpiresAt = f.at.Add(time.Second)
	long := f.member("act_long", "203.0.113.20")
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })
	writeFirewallStateJSON = func(path string, mode os.FileMode, v any) error {
		err := prev(path, mode, v)
		f.at = f.at.Add(2 * time.Second)
		return err
	}
	f.onFlush = func() { f.live[long.IP], f.expires[long.IP] = time.Hour-2*time.Second, time.Hour-2*time.Second }
	got, err := f.e.ApplyBlockBatch([]BlockMember{short, long})
	if err != nil || effects(got) != "failed/expired applied/" || f.sends != 1 || f.e.IsBlocked(short.IP) {
		t.Fatalf("results %+v, %v, sends %d", got, err, f.sends)
	}
	if strings.Join(f.audited(t), ",") != "block 203.0.113.20" {
		t.Fatal("expired member audited")
	}
}

func TestApplyBlockBatchPostWriteSubMillisecondRefusalIsNotReported(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	m := f.member("act_short", "203.0.113.20")
	m.ExpiresAt = f.at.Add(time.Millisecond)
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })
	writeFirewallStateJSON = func(path string, mode os.FileMode, v any) error {
		err := prev(path, mode, v)
		f.at = f.at.Add(500 * time.Microsecond)
		return err
	}
	got, err := f.e.ApplyBlockBatch([]BlockMember{m})
	if err != nil || effects(got) != "failed/expired" || f.sends != 0 || f.e.IsBlocked(m.IP) || f.e.BlockedCount() != 0 {
		t.Fatalf("results %+v, %v, sends %d; a refused row must not be reported", got, err, f.sends)
	}
}

// After a failed intent write the batch hold stays until the owner writes
// the safe state again; marking (even nothing) is that write.
func TestMarkReleasesTheBatchHoldAfterAFailedIntentWrite(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })
	writeFirewallStateJSON = func(string, os.FileMode, any) error { return errors.New("disk full") }
	member := f.member("act_v4", "203.0.113.20")
	if results, err := f.e.ApplyBlockBatch([]BlockMember{member}); err != nil || effects(results) != "failed/" || !errors.Is(results[0].Err, ErrBlockBatchState) {
		t.Fatalf("apply = %s, %v", effects(results), err)
	}
	if _, err := f.e.CheckBlockBatch([]BlockMember{member}); !errors.Is(err, ErrBlockBatchState) {
		t.Fatalf("check during the hold = %v, want ErrBlockBatchState", err)
	}

	writeFirewallStateJSON = prev // storage recovered
	writes := f.countWrites(t)
	if marked, err := f.e.MarkBlockActionsUnverified(nil); err != nil || marked != 0 || *writes != 1 {
		t.Fatalf("mark = %d, %v with %d writes; want the safe state written once", marked, err, *writes)
	}
	if got, err := f.e.CheckBlockBatch([]BlockMember{member}); err != nil || got[0] != "" {
		t.Fatalf("check after release = %q, %v", got, err)
	}
	if _, ok := f.storedRows(t)[member.IP]; ok {
		t.Fatal("the failed member's row was written back")
	}
	if marked, err := f.e.MarkBlockActionsUnverified(nil); err != nil || marked != 0 || *writes != 1 {
		t.Fatalf("second mark = %d, %v with %d writes; want no write without a hold", marked, err, *writes)
	}
}
