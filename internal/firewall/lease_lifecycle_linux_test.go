//go:build linux

package firewall

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/userdata"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func TestLeaseDurableActionTimeouts(t *testing.T) {
	for _, mode := range []string{"delta", "rewrite", "retry", "expired"} {
		t.Run(mode, func(t *testing.T) {
			at := time.Now().Round(0)
			clock := &leaseSteps{wall: at, elapsed: at}
			conn, captured := capturingLifecycleConn(t, func(attempt int) bool {
				if mode == "retry" && attempt == 1 {
					clock.advance(time.Minute)
					clock.step(-time.Hour)
					return true
				}
				return false
			})
			e := newBlockedSetWireTestEngine(t, conn)
			e.leaseClock, e.expiryClock = clock.read, func() time.Time { return clock.wall }
			clock.step(2 * time.Hour)
			deadline := leaseNow(e).Add(time.Hour)
			clock.step(-2 * time.Hour)
			clock.advance(time.Minute)
			if mode == "expired" {
				clock.advance(time.Hour)
			}
			before := ActionSet{Name: "blocked_ips", Exists: true}
			a := FirewallAction{KernelBefore: []ActionSet{before}, KernelAfter: []ActionSet{{Name: before.Name, Exists: true, Elements: []ActionElement{
				{Key: []byte{192, 0, 2, 152}, ExpiresAt: deadline},
			}}}}
			if mode == "rewrite" {
				a.KernelBefore = nil
			}
			e.mu.Lock()
			err := (engineActionKernel{e}).ApplyFirewallAction(a)
			e.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
			if mode == "expired" {
				if len(timeouts) != 0 {
					t.Fatal("durable action restored an expired lease")
				}
				return
			}
			want := 59 * time.Minute
			if mode == "retry" {
				want -= time.Minute
			}
			if len(timeouts) != 1 || timeouts[0] == nil || *timeouts[0] != want {
				t.Fatalf("durable timeout = %v, want exactly %v", timeouts, want)
			}
		})
	}
}

// Return an IPv4 set dump with independently specified kernel time left.
func leaseActionReadConn(t *testing.T, elements []nftables.SetElement) *nftables.Conn {
	t.Helper()
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, io.EOF
		}
		msg := req[0]
		if strings.Contains(string(msg.Data), "blocked_ips6") {
			return nltest.Error(int(unix.ENOENT), req)
		}
		switch uint16(msg.Header.Type) & 0xff {
		case unix.NFT_MSG_GETSET:
			msg.Header.Type = netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWSET)
		case unix.NFT_MSG_GETSETELEM:
			encoder := netlink.NewAttributeEncoder()
			encoder.ByteOrder = binary.BigEndian
			encoder.Nested(unix.NFTA_SET_ELEM_LIST_ELEMENTS, func(list *netlink.AttributeEncoder) error {
				for _, elem := range elements {
					list.Nested(unix.NFTA_LIST_ELEM, func(item *netlink.AttributeEncoder) error {
						item.Nested(unix.NFTA_SET_ELEM_KEY, func(key *netlink.AttributeEncoder) error {
							key.Bytes(unix.NFTA_DATA_VALUE, elem.Key)
							return nil
						})
						item.Uint64(unix.NFTA_SET_ELEM_TIMEOUT, uint64(elem.Timeout.Milliseconds()))
						item.Uint64(unix.NFTA_SET_ELEM_EXPIRATION, uint64(elem.Expires.Milliseconds()))
						item.Bytes(unix.NFTA_SET_ELEM_USERDATA, userdata.AppendString(nil, userdata.NFTNL_UDATA_SET_ELEM_COMMENT, elem.Comment))
						return nil
					})
				}
				return nil
			})
			data, err := encoder.Encode()
			if err != nil {
				return nil, err
			}
			msg.Data = append(append([]byte(nil), msg.Data[:4]...), data...)
			msg.Header.Type = netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWSETELEM)
		default:
			return nil, errors.New("unexpected mutation in read-only fixture")
		}
		msg.Header.Flags = 0
		return []netlink.Message{msg}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestLeaseDurablePlanningAndObservation(t *testing.T) {
	at := time.Now().Round(0)
	clock := &leaseSteps{wall: at, elapsed: at}
	row := BlockedEntry{IP: "192.0.2.152", ExpiresAt: at.Add(3 * time.Hour)}
	state := FirewallState{Blocked: []BlockedEntry{row}}
	conn := leaseActionReadConn(t, []nftables.SetElement{{Key: []byte{192, 0, 2, 152}, Comment: stateFingerprint(row), Timeout: time.Hour, Expires: 59 * time.Minute}})
	e := deltaTestEngine(t, conn)
	e.leaseClock, e.expiryClock = clock.read, func() time.Time { return clock.wall }
	e.SetLeaseFloor(at.Add(2 * time.Hour))
	clock.advance(time.Minute)
	e.mu.Lock()
	defer e.mu.Unlock()
	a := FirewallAction{Request: ActionRequest{Operation: "unblock"}, Before: state}
	if err := e.prepareActionKernel(&a); err != nil {
		t.Fatalf("valid lease rejected during planning: %v", err)
	}
	if len(a.KernelBefore) != 2 || len(a.KernelBefore[0].Elements) != 1 || !a.KernelBefore[0].Elements[0].ExpiresAt.Equal(row.ExpiresAt) {
		t.Fatalf("planning changed the original deadline: %+v", a.KernelBefore)
	}
	observation, err := (engineActionKernel{e}).ObserveFirewallAction(a)
	if err != nil || !observation.Before || observation.After {
		t.Fatalf("valid lease not recognized before execution: %+v, %v", observation, err)
	}
	a.Before, a.After = a.After, a.Before
	a.KernelBefore, a.KernelAfter = a.KernelAfter, a.KernelBefore
	observation, err = (engineActionKernel{e}).ObserveFirewallAction(a)
	if err != nil || observation.Before || !observation.After {
		t.Fatalf("valid lease not recognized after execution: %+v, %v", observation, err)
	}
}

type leaseIntentStore struct {
	replayLifecycleStore
	admit func(FirewallAction) (FirewallAction, bool, error)
}

func (s leaseIntentStore) ReadFirewallAction(string) (FirewallAction, error) {
	return FirewallAction{}, ErrActionMissing
}
func (s leaseIntentStore) AdmitFirewallAction(a FirewallAction) (FirewallAction, bool, error) {
	return s.admit(a)
}

func TestLeaseDurableBlockRefusesFailedCheckpoint(t *testing.T) {
	conn := leaseActionReadConn(t, nil)
	e := newBlockedSetWireTestEngine(t, conn)
	cause := errors.New("fixture checkpoint unavailable")
	e.SetBootClock(func() (string, time.Duration, error) { return "", 0, cause })
	admitted := false
	if err := e.AttachLifecycle(&Lifecycle{Store: leaseIntentStore{admit: func(FirewallAction) (FirewallAction, bool, error) {
		admitted = true
		return FirewallAction{}, false, errors.New("intent reached")
	}}}); err != nil {
		t.Fatal(err)
	}
	err := e.BlockIPForce("192.0.2.152", "operator", time.Hour)
	if !errors.Is(err, cause) || admitted {
		t.Fatalf("checkpoint failure did not stop durable intent: admitted=%t, err=%v", admitted, err)
	}
}

func TestLeaseDurableApplyResumesBeforePlanning(t *testing.T) {
	at := time.Now().Round(0)
	clock := &leaseSteps{wall: at, elapsed: at}
	boot := &bootReading{id: leaseBootA, since: time.Hour}
	dir := t.TempDir()
	saveLease(t, checkpointEngine(dir, &leaseSteps{wall: at.Add(2 * time.Hour), elapsed: at}, boot))
	e := checkpointEngine(dir, clock, boot)
	cause := errors.New("stop after inspecting planning clock")
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, io.EOF
		}
		if got := e.leaseNowLocked(); !got.Equal(at.Add(2 * time.Hour)) {
			t.Errorf("ruleset planning used %v before resuming checkpoint", got)
		}
		return nil, cause
	}))
	if err != nil {
		t.Fatal(err)
	}
	e.conn = conn
	if err := e.AttachLifecycle(&Lifecycle{Store: replayLifecycleStore{}}); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(); !errors.Is(err, cause) {
		t.Fatalf("planning error = %v, want fixture stop", err)
	}
}
