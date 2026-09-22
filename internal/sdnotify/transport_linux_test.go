//go:build linux

package sdnotify

import (
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestNotifyAbstractSocket(t *testing.T) {
	name := fmt.Sprintf("csm-notify-%d-%d", os.Getpid(), time.Now().UnixNano())
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: "\x00" + name, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	t.Setenv("NOTIFY_SOCKET", "@"+name)
	Capture()
	if sent, err := Ready(); !sent || err != nil {
		t.Fatalf("abstract notification: sent=%v err=%v", sent, err)
	}
	if got := readDatagram(t, conn); got != "READY=1" {
		t.Fatalf("abstract socket received %q", got)
	}
}

func TestConcurrentStatusAndWatchdog(t *testing.T) {
	conn, path := notifyListener(t)
	t.Setenv("NOTIFY_SOCKET", path)
	Capture()
	const pairs = 32
	errs := make(chan error, pairs*2)
	var senders sync.WaitGroup
	for i := 0; i < pairs; i++ {
		for _, send := range []func() (bool, error){Watchdog, func() (bool, error) { return Status("running") }} {
			senders.Add(1)
			go func() {
				defer senders.Done()
				if sent, err := send(); !sent || err != nil {
					errs <- fmt.Errorf("sent=%v err=%v", sent, err)
				}
			}()
		}
	}
	counts := make(map[string]int)
	for i := 0; i < pairs*2; i++ {
		counts[readDatagram(t, conn)]++
	}
	senders.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if len(counts) != 2 || counts["WATCHDOG=1"] != pairs || counts["STATUS=running"] != pairs {
		t.Fatalf("lost or mixed concurrent datagrams: %v", counts)
	}
}

func TestNotifyReturnsWhenSocketQueueIsFull(t *testing.T) {
	conn, path := notifyListener(t)
	filler, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = filler.Close() }()
	if err := filler.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := filler.Write([]byte("fill")); err != nil {
			if e, ok := err.(net.Error); !ok || !e.Timeout() {
				t.Fatalf("fill notification queue: %v", err)
			}
			break
		}
	}
	t.Setenv("NOTIFY_SOCKET", path)
	Capture()
	done := make(chan error, 1)
	go func() {
		sent, err := Watchdog()
		if sent || err == nil {
			done <- fmt.Errorf("full socket: sent=%v err=%v", sent, err)
			return
		}
		if e, ok := err.(net.Error); !ok || !e.Timeout() {
			done <- fmt.Errorf("expected timeout, got %v", err)
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		_ = conn.Close()
		<-done
		t.Fatal("notification blocked on a full socket queue")
	}
}
