//go:build linux

package firewall

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func TestLifecycleSocketDeadlineInterruptsSilentKernel(t *testing.T) {
	socket, err := netlink.Dial(unix.NETLINK_USERSOCK, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	if deadlineErr := applyLifecycleSocketDeadline(socket); deadlineErr != nil {
		t.Fatal(deadlineErr)
	}
	// Receive has no producer. Only the socket deadline can release this call.
	started := time.Now()
	_, err = socket.Receive()
	if !os.IsTimeout(err) {
		t.Fatalf("silent netlink receive did not time out: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("deadline did not bound kernel wait: %s", elapsed)
	}
	_, err = socket.Send(netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(unix.NLMSG_MIN_TYPE)}})
	if !os.IsTimeout(err) {
		t.Fatalf("write deadline was not installed with read deadline: %v", err)
	}
}

func TestLifecycleSocketRejectsUnsupportedLiveDeadline(t *testing.T) {
	socket := nltest.Dial(func([]netlink.Message) ([]netlink.Message, error) { return nil, nil })
	t.Cleanup(func() { _ = socket.Close() })
	if err := applyLifecycleSocketDeadline(socket); err == nil {
		t.Fatal("unsupported deadline silently disabled live bound")
	}
}

func TestLifecycleConnectionPreservesExplicitTestTransport(t *testing.T) {
	want := errors.New("test transport reached")
	engine := &Engine{conn: &nftables.Conn{NetNS: 37, TestDial: func([]netlink.Message) ([]netlink.Message, error) { return nil, want }}}
	connection, err := newLifecycleConn(engine)
	if err != nil {
		t.Fatal(err)
	}
	if connection.NetNS != 37 {
		t.Fatalf("network namespace lost: %d", connection.NetNS)
	}
	// nltest sockets do not implement deadlines. The explicit test transport
	// remains usable; live transports must never take this exception.
	_, err = connection.ListTables()
	if !errors.Is(err, want) {
		t.Fatalf("explicit test transport lost: %v", err)
	}
}

func TestLifecycleConnectionRequiresEngineTransport(t *testing.T) {
	for _, engine := range []*Engine{nil, {}} {
		if _, err := newLifecycleConn(engine); err == nil {
			t.Fatal("missing engine transport accepted")
		}
	}
}
