//go:build linux

package firewall

import (
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

const nftDeleteSetElem = uint16(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_DELSETELEM)

// capturingLifecycleConn records every netlink message an apply sends. The
// engine builds its transport with newLifecycleConn, so the recorder is
// installed as the engine connection's test dial.
func capturingLifecycleConn(t *testing.T, fail func(attempt int) bool) (*nftables.Conn, *[]netlink.Message) {
	t.Helper()
	captured := &[]netlink.Message{}
	attempt := 0
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, io.EOF
		}
		attempt++
		if fail != nil && fail(attempt) {
			return nltest.Error(int(unix.ENOENT), req)
		}
		*captured = append(*captured, req...)
		acks := make([]netlink.Message, 0, len(req))
		for _, msg := range req {
			if msg.Header.Flags&netlink.Acknowledge == 0 {
				continue
			}
			acks = append(acks, netlink.Message{
				Header: netlink.Header{Length: 4, Type: netlink.Error, Sequence: msg.Header.Sequence, PID: msg.Header.PID},
				Data:   []byte{0, 0, 0, 0},
			})
		}
		return acks, nil
	}))
	if err != nil {
		t.Fatalf("test connection: %v", err)
	}
	return conn, captured
}

func capturedBytes(messages []netlink.Message) int {
	total := 0
	for _, msg := range messages {
		total += len(msg.Data)
	}
	return total
}

func capturedTypes(messages []netlink.Message, want uint16) int {
	count := 0
	for _, msg := range messages {
		if uint16(msg.Header.Type) == want {
			count++
		}
	}
	return count
}

// populatedBlockAction returns a plan whose live set already holds many
// entries, which is what a production host looks like when one address is
// added or removed.
func populatedBlockAction(t *testing.T, operation string) FirewallAction {
	t.Helper()
	var elements []ActionElement
	for i := range 500 {
		prefix := [][3]byte{{192, 0, 2}, {198, 51, 100}}[i/250]
		elements = append(elements, ActionElement{Key: []byte{prefix[0], prefix[1], prefix[2], byte(i%250 + 1)}, Comment: "csm:existing"})
	}
	added := ActionElement{Key: []byte{203, 0, 113, 7}, Comment: "csm:changed"}
	before := ActionSet{Name: "blocked_ips", Exists: true, Elements: elements}
	after := ActionSet{Name: "blocked_ips", Exists: true, Elements: append(append([]ActionElement(nil), elements...), added)}
	if operation == "unblock" {
		before, after = after, before
	}
	return FirewallAction{
		Request:      ActionRequest{ID: "delta", Operation: operation, Target: "203.0.113.7", Actor: "cli", Source: "cli"},
		KernelBefore: []ActionSet{before},
		KernelAfter:  []ActionSet{after},
		CreatedAt:    time.Now(),
	}
}

func deltaTestEngine(t *testing.T, conn *nftables.Conn) *Engine {
	t.Helper()
	e := newTestEngine(t)
	e.conn = conn
	e.setBlocked = namedIPv4Set("blocked_ips")
	return e
}

func TestDurableApplySendsOnlyChangedElements(t *testing.T) {
	for _, operation := range []string{"block", "unblock"} {
		t.Run(operation, func(t *testing.T) {
			conn, captured := capturingLifecycleConn(t, nil)
			e := deltaTestEngine(t, conn)
			if err := (engineActionKernel{e}).ApplyFirewallAction(populatedBlockAction(t, operation)); err != nil {
				t.Fatalf("apply: %v", err)
			}
			// A complete rewrite of 500 retained entries costs tens of
			// kilobytes; one changed element costs a few hundred bytes.
			if size := capturedBytes(*captured); size > 4096 {
				t.Fatalf("apply sent %d bytes, want only the changed element", size)
			}
			if operation == "block" && capturedTypes(*captured, nftDeleteSetElem) != 0 {
				t.Fatal("an added element must not flush or delete set elements")
			}
		})
	}
}

func TestDurableApplyRewritesSetWhenDeleteTargetIsGone(t *testing.T) {
	// The kernel expires timed elements on its own, so a delete can race a
	// removal that is already gone. The rewrite converges to the same state.
	conn, captured := capturingLifecycleConn(t, func(attempt int) bool { return attempt == 1 })
	e := deltaTestEngine(t, conn)
	if err := (engineActionKernel{e}).ApplyFirewallAction(populatedBlockAction(t, "unblock")); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if capturedTypes(*captured, nftDeleteSetElem) == 0 {
		t.Fatal("the fallback must flush the set before re-adding it")
	}
	if size := capturedBytes(*captured); size < 4096 {
		t.Fatalf("fallback sent %d bytes, want a complete rewrite", size)
	}
}

func bulkRemovalAction() FirewallAction {
	var elements []ActionElement
	for i := range 5001 {
		key := make([]byte, 16)
		copy(key, []byte{0x20, 0x01, 0x0d, 0xb8})
		binary.BigEndian.PutUint32(key[12:], uint32(i))
		elements = append(elements, ActionElement{Key: key})
	}
	return FirewallAction{
		KernelBefore: []ActionSet{{Name: "blocked_ips6", Exists: true, Elements: elements}},
		KernelAfter:  []ActionSet{{Name: "blocked_ips6", Exists: true, Elements: elements[:1]}},
	}
}

func TestDurableApplyBulkRemovalEncodesEveryElement(t *testing.T) {
	conn, captured := capturingLifecycleConn(t, nil)
	e := deltaTestEngine(t, conn)
	e.setBlocked6 = namedIPv4Set("blocked_ips6")
	e.setBlocked6.KeyType = nftables.TypeIP6Addr
	a := bulkRemovalAction()
	if err := (engineActionKernel{e}).ApplyFirewallAction(a); err != nil {
		t.Fatal(err)
	}
	removed := make(map[uint32]bool)
	for _, msg := range *captured {
		if uint16(msg.Header.Type) != nftDeleteSetElem {
			continue
		}
		attrs, err := netlink.UnmarshalAttributes(msg.Data[4:])
		if err != nil {
			t.Fatalf("invalid removal message: %v", err)
		}
		for _, attr := range attrs {
			if attr.Type&0x3fff != unix.NFTA_SET_ELEM_LIST_ELEMENTS {
				continue
			}
			items, err := netlink.UnmarshalAttributes(attr.Data)
			if err != nil {
				t.Fatalf("invalid removal list: %v", err)
			}
			for _, item := range items {
				fields, err := netlink.UnmarshalAttributes(item.Data)
				if err != nil {
					t.Fatal(err)
				}
				for _, field := range fields {
					if field.Type&0x3fff != unix.NFTA_SET_ELEM_KEY {
						continue
					}
					values, err := netlink.UnmarshalAttributes(field.Data)
					if err != nil || len(values) != 1 || len(values[0].Data) != 16 {
						t.Fatalf("invalid removal key: %v", err)
					}
					id := binary.BigEndian.Uint32(values[0].Data[12:])
					if id == 0 || id > 5000 || removed[id] {
						t.Fatalf("unexpected or duplicate removal: %d", id)
					}
					removed[id] = true
				}
			}
		}
	}
	if len(removed) != 5000 {
		t.Fatalf("encoded %d removals, want 5000", len(removed))
	}
	if capturedTypes(*captured, unix.NFNL_MSG_BATCH_BEGIN) != 1 || capturedTypes(*captured, unix.NFNL_MSG_BATCH_END) != 1 {
		t.Fatal("bulk removal must remain one atomic batch")
	}
}

func TestDurableApplyPropagatesKernelFailures(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EPERM, unix.ENOENT} {
		t.Run(errno.Error(), func(t *testing.T) {
			conn, sends := nftConnReturningErrsThenOK(t, errno, unix.EIO)
			e := deltaTestEngine(t, conn)
			err := (engineActionKernel{e}).ApplyFirewallAction(populatedBlockAction(t, "unblock"))
			wantErr, wantSends := errno, 1
			if errno == unix.ENOENT {
				wantErr, wantSends = unix.EIO, 2
			}
			if !errors.Is(err, wantErr) || sends() != wantSends {
				t.Fatalf("apply error=%v sends=%d, want %v and %d", err, sends(), wantErr, wantSends)
			}
		})
	}
}

func TestActionDeltaPreservesExpiryAndMetadata(t *testing.T) {
	now := time.Now()
	key := []byte{192, 0, 2, 7}
	before := ActionElement{Key: key, Comment: "original", ExpiresAt: now.Add(time.Hour)}
	for _, tc := range []struct {
		name    string
		after   ActionElement
		changed bool
		timeout time.Duration
	}{
		{"unchanged", before, false, time.Hour},
		{"comment", ActionElement{Key: key, Comment: "changed", ExpiresAt: before.ExpiresAt}, true, time.Hour},
		{"renewed", ActionElement{Key: key, Comment: before.Comment, ExpiresAt: now.Add(2 * time.Hour)}, true, 2 * time.Hour},
		{"permanent", ActionElement{Key: key, Comment: before.Comment}, true, 0},
		{"expired", ActionElement{Key: key, Comment: before.Comment, ExpiresAt: now.Add(-time.Second)}, true, -1},
		{"sub-millisecond", ActionElement{Key: key, Comment: before.Comment, ExpiresAt: now.Add(time.Microsecond)}, true, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			add, remove := actionElementDelta(ActionSet{Elements: []ActionElement{before}}, ActionSet{Elements: []ActionElement{tc.after}}, now)
			var wantAdd, wantRemove []nftables.SetElement
			if tc.changed {
				wantRemove = []nftables.SetElement{{Key: key}}
				if tc.timeout >= 0 {
					wantAdd = []nftables.SetElement{{Key: key, Comment: tc.after.Comment, Timeout: tc.timeout}}
				}
			}
			if !reflect.DeepEqual(add, wantAdd) || !reflect.DeepEqual(remove, wantRemove) {
				t.Fatalf("add=%+v remove=%+v, want %+v and %+v", add, remove, wantAdd, wantRemove)
			}
		})
	}
}
