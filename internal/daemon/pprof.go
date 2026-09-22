package daemon

import (
	"net"
	"net/http"
	"net/http/pprof"
	"runtime"
	"strings"
	"sync"
	"time"

	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/obs"
)

const (
	// mutexProfileFraction samples one in every N mutex contention events.
	// Sampling limits stack collection overhead on busy hosts.
	mutexProfileFraction = 100

	// blockProfileRate samples one blocking event per this many nanoseconds
	// spent blocked, so a goroutine parked for 10 microseconds is recorded
	// with probability one. Shorter waits are sampled with proportionally lower
	// probability, not excluded. Even unsampled waits incur timing overhead.
	blockProfileRate = 10_000
)

// The runtime rates are process-wide. A listener stopping must not switch off
// another listener that is still serving profiles.
var contentionProfiles struct {
	sync.Mutex
	listeners int
}

// enableContentionProfiles turns on the sampling the mutex and block profiles
// depend on for the lifetime of successfully bound listeners.
func enableContentionProfiles() {
	contentionProfiles.Lock()
	defer contentionProfiles.Unlock()
	if contentionProfiles.listeners == 0 {
		runtime.SetMutexProfileFraction(mutexProfileFraction)
		runtime.SetBlockProfileRate(blockProfileRate)
	}
	contentionProfiles.listeners++
}

func disableContentionProfiles() {
	contentionProfiles.Lock()
	defer contentionProfiles.Unlock()
	contentionProfiles.listeners--
	if contentionProfiles.listeners == 0 {
		runtime.SetMutexProfileFraction(0)
		runtime.SetBlockProfileRate(0)
	}
}

// pprofListen is replaceable in tests so listener lifecycle coverage does not
// depend on the test sandbox allowing real sockets.
var pprofListen = net.Listen

// isLoopbackPprofAddr reports whether addr (host:port) binds only to a loopback
// interface. The pprof server exposes process internals and lets a caller
// trigger CPU/heap dumps, so it must never listen off-box. An empty or wildcard
// host ("" / ":6060") is rejected because it would bind all interfaces.
func isLoopbackPprofAddr(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newPprofMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// startPprofListener starts a net/http/pprof server on addr, but only when addr
// is a loopback bind. A dedicated mux keeps the pprof handlers off
// http.DefaultServeMux so nothing else can serve them. The listener closes on
// daemon shutdown. It reports whether a listener was actually started.
func (d *Daemon) startPprofListener(addr string) bool {
	if !isLoopbackPprofAddr(addr) {
		csmlog.Warn("debug.pprof_listen ignored: not a loopback bind; pprof exposes process internals and must use 127.0.0.1/::1/localhost",
			"addr", addr)
		return false
	}

	ln, err := pprofListen("tcp", strings.TrimSpace(addr))
	if err != nil {
		csmlog.Warn("debug.pprof_listen ignored: listener failed", "addr", addr, "err", err)
		return false
	}

	// Sampling starts with the listener, not at daemon start: a host with no
	// pprof bind pays nothing for profiles nobody can fetch.
	enableContentionProfiles()

	srv := &http.Server{
		Addr:              addr,
		Handler:           newPprofMux(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	done := make(chan struct{})
	d.wg.Add(2)
	obs.Go("pprof-listener", func() {
		defer d.wg.Done()
		defer close(done)

		csmlog.Info("pprof debug listener started", "addr", ln.Addr().String())
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			csmlog.Warn("pprof listener stopped", "err", err)
		}
	})
	obs.Go("pprof-shutdown", func() {
		defer d.wg.Done()
		defer disableContentionProfiles()
		select {
		case <-d.stopCh:
			_ = srv.Close()
		case <-done:
		}
	})
	return true
}
