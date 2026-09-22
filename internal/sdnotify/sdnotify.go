// Package sdnotify talks to the systemd notification socket. The daemon calls
// Ready when watchers are attached, Status to publish a one-line state visible
// in `systemctl status`, and Watchdog on a recurring ticker so systemd's
// WatchdogSec= keep-alive doesn't expire.
//
// Capture takes the systemd variables out of the process environment at
// startup and keeps them here. Everything the daemon executes afterwards --
// the PHP taint worker, every command a check shells out to -- would otherwise
// inherit NOTIFY_SOCKET and be able to write to it. The unit declares
// NotifyAccess=main, so each of those children produced a "notification
// message from PID ..., but reception only permitted for main PID" line in the
// journal. Scrubbing once at the source is what keeps a spawn site added later
// from reintroducing it.
//
// Every function is a no-op when no socket was captured (the daemon is not
// running under systemd; e.g. dev mode). That contract makes it safe to call
// these helpers unconditionally without runtime gates in the daemon code.
package sdnotify

import (
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// systemdEnv are the variables systemd passes to a service that must not reach
// any child process. Only the first two are used here; the rest describe
// socket activation this daemon does not use, and a child that read them would
// act on descriptors it was never given.
var systemdEnv = []string{
	"NOTIFY_SOCKET",
	"WATCHDOG_USEC",
	"WATCHDOG_PID",
	"LISTEN_FDS",
	"LISTEN_PID",
	"LISTEN_FDNAMES",
}

var (
	mu              sync.RWMutex
	socket          string
	watchdogTimeout time.Duration
)

// Capture reads the systemd notification environment and removes it from the
// process environment. Called once, before the daemon spawns anything.
// Re-reading on a later call is intentional and lets tests drive it.
func Capture() {
	addr := os.Getenv("NOTIFY_SOCKET")
	timeout := parseWatchdogTimeout(os.Getenv("WATCHDOG_USEC"))
	for _, name := range systemdEnv {
		_ = os.Unsetenv(name)
	}
	mu.Lock()
	socket, watchdogTimeout = addr, timeout
	mu.Unlock()
}

func parseWatchdogTimeout(usec string) time.Duration {
	if usec == "" {
		return 0
	}
	parsed, err := strconv.ParseInt(usec, 10, 64)
	if err != nil || parsed <= 0 {
		return 0
	}
	return time.Duration(parsed) * time.Microsecond
}

// WatchdogTimeout reports the interval systemd expects keepalives within, and
// whether the unit configured one at all.
func WatchdogTimeout() (time.Duration, bool) {
	mu.RLock()
	defer mu.RUnlock()
	return watchdogTimeout, watchdogTimeout > 0
}

// Enabled reports whether a notification socket was captured, i.e. whether
// this process is running under systemd with notifications configured.
func Enabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	return socket != ""
}

// notify sends one datagram to the captured socket. Returns (true, nil) when
// the notification was delivered, (false, nil) when no socket was captured, or
// (false, err) on a real I/O error.
func notify(state string) (bool, error) {
	mu.RLock()
	addr := socket
	mu.RUnlock()
	if addr == "" {
		return false, nil
	}
	// A leading "@" marks an abstract socket name; the syscall layer turns it
	// into the leading NUL byte the kernel expects.
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	// A bound socket can stop draining its queue. Do not let a notification
	// hold startup, status updates or watchdog shutdown indefinitely.
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return false, err
	}
	if _, err := conn.Write([]byte(state)); err != nil {
		return false, err
	}
	return true, nil
}

// Ready signals systemd that the daemon has finished startup.
func Ready() (bool, error) {
	return notify("READY=1")
}

// Reloading signals systemd that the daemon is reloading its config.
func Reloading() (bool, error) {
	return notify("RELOADING=1")
}

// Status sets a single-line status string visible in `systemctl status csm`.
func Status(msg string) (bool, error) {
	return notify("STATUS=" + msg)
}

// Watchdog pings the systemd watchdog. Required when the unit declares
// WatchdogSec=; without periodic pings systemd will restart the daemon
// after WatchdogSec elapses.
func Watchdog() (bool, error) {
	return notify("WATCHDOG=1")
}
