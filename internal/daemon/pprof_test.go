package daemon

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func TestIsLoopbackPprofAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:6060", true},
		{" 127.0.0.1:6060 ", true},
		{"[::1]:6060", true},
		{"localhost:6060", true},
		{"0.0.0.0:6060", false}, // wildcard binds all interfaces
		{":6060", false},        // empty host = all interfaces
		{"[::]:6060", false},
		{"192.168.1.10:6060", false},
		{"10.0.0.5:6060", false},
		{"203.0.113.7:6060", false},
		{"", false},
		{"127.0.0.1", false}, // missing port
	}
	for _, c := range cases {
		if got := isLoopbackPprofAddr(c.addr); got != c.want {
			t.Errorf("isLoopbackPprofAddr(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestPprofLoopbackValidationMatchesRuntime(t *testing.T) {
	cases := []string{
		"127.0.0.1:6060",
		" 127.0.0.1:6060 ",
		"[::1]:6060",
		"localhost:6060",
		"0.0.0.0:6060",
		":6060",
		"[::]:6060",
		"192.168.1.10:6060",
		"203.0.113.7:6060",
		"127.0.0.1",
	}
	for _, addr := range cases {
		cfg := &config.Config{}
		cfg.Debug.PprofListen = addr
		results := config.Validate(cfg)
		runtimeOK := isLoopbackPprofAddr(addr)

		if runtimeOK && !hasPprofValidationResult(results, "ok") {
			t.Errorf("Validate(%q) did not accept runtime-safe loopback addr: %v", addr, results)
		}
		if !runtimeOK && !hasPprofValidationResult(results, "error") {
			t.Errorf("Validate(%q) did not reject runtime-unsafe addr: %v", addr, results)
		}
	}
}

func TestPprofMuxServesSubProfilesThroughIndex(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/debug/pprof/heap?debug=1", "heap profile"},
		{"/debug/pprof/goroutine?debug=1", "goroutine profile"},
		{"/debug/pprof/allocs?debug=1", "heap profile"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, c.path, nil)
		rr := httptest.NewRecorder()

		newPprofMux().ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want %d; body=%s", c.path, rr.Code, http.StatusOK, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), c.want) {
			t.Fatalf("%s sub-profile did not come from pprof.Index; body=%s", c.path, rr.Body.String())
		}
	}
}

func TestStartPprofListenerRejectsNonLoopbackWithoutWorker(t *testing.T) {
	d := &Daemon{stopCh: make(chan struct{})}
	if d.startPprofListener("0.0.0.0:6060") {
		t.Fatal("non-loopback pprof listener started")
	}

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("non-loopback pprof listener registered a worker")
	}
}

func TestStartPprofListenerBindFailureDoesNotRegisterWorker(t *testing.T) {
	withPprofListen(t, func(string, string) (net.Listener, error) {
		return nil, errTestPprofListen
	})

	d := &Daemon{stopCh: make(chan struct{})}
	if d.startPprofListener("127.0.0.1:6060") {
		t.Fatal("pprof listener started after listen failure")
	}

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed pprof listen registered a worker")
	}
}

func TestStartPprofListenerStopsOnDaemonStop(t *testing.T) {
	ln := newBlockingPprofListener("127.0.0.1:6060")
	withPprofListen(t, func(network, address string) (net.Listener, error) {
		if network != "tcp" {
			t.Fatalf("network = %q, want tcp", network)
		}
		if address != "127.0.0.1:6060" {
			t.Fatalf("address = %q, want 127.0.0.1:6060", address)
		}
		return ln, nil
	})

	d := &Daemon{stopCh: make(chan struct{})}
	if !d.startPprofListener("127.0.0.1:6060") {
		t.Fatal("pprof listener did not start")
	}

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("pprof listener exited before daemon stop")
	case <-time.After(50 * time.Millisecond):
	}

	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pprof listener did not stop after daemon stop")
	}
}

type pprofListenErr struct{}

func (pprofListenErr) Error() string { return "pprof listen failed" }

var errTestPprofListen pprofListenErr

func withPprofListen(t *testing.T, listen func(string, string) (net.Listener, error)) {
	t.Helper()
	old := pprofListen
	pprofListen = listen
	t.Cleanup(func() { pprofListen = old })
}

type blockingPprofListener struct {
	closed chan struct{}
	once   sync.Once
	addr   net.Addr
}

func newBlockingPprofListener(addr string) *blockingPprofListener {
	return &blockingPprofListener{
		closed: make(chan struct{}),
		addr:   pprofAddr(addr),
	}
}

func (l *blockingPprofListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingPprofListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *blockingPprofListener) Addr() net.Addr { return l.addr }

type pprofAddr string

func (a pprofAddr) Network() string { return "tcp" }

func (a pprofAddr) String() string { return string(a) }

func hasPprofValidationResult(results []config.ValidationResult, level string) bool {
	for _, result := range results {
		if result.Field == "debug.pprof_listen" && result.Level == level {
			return true
		}
	}
	return false
}
