package config

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// clamdSocketCandidates are the unix sockets a clamd is normally reachable on.
// The path is set by whoever packaged clamd, not by CSM: RHEL's clamd-scan,
// Debian's clamav-daemon and cPanel's bundled clamd all choose differently, and
// a host whose setting names the wrong one scans no mail at all while every
// health signal still reports the watcher as running.
//
// Every entry is a root-owned service directory. A world-writable location such
// as /tmp is deliberately absent: any account could bind a socket there, and
// CSM would then stream every attachment to it and believe the "OK" it answers.
var clamdSocketCandidates = []string{
	"/var/run/clamd.scan/clamd.sock",
	"/run/clamd.scan/clamd.sock",
	"/var/run/clamav/clamd.ctl",
	"/run/clamav/clamd.ctl",
	"/var/run/clamav/clamd.sock",
	"/run/clamav/clamd.sock",
	"/usr/local/cpanel/3rdparty/var/clamav/clamd.sock",
}

// clamdDialTimeout bounds each probe. The candidate list is walked on a health
// path, so a hung socket must not hold the caller. A real clamd that is merely
// busy still answers PING promptly; it is a separate thread from scanning.
const clamdDialTimeout = 2 * time.Second

// ResolveClamdSocket returns the socket to talk to clamd on, and whether it had
// to be discovered because the configured one was not answering.
//
// The configured path always wins when clamd is answering on it. Only when it
// is not does CSM fall back to a well-known location, because refusing to scan
// mail is the worse failure: silence there looks exactly like clean mail.
//
// A discovered socket is only accepted when it is owned by root or by this
// process and sits in a directory no other account can write to, and when
// whatever is listening answers clamd's PING. Discovery must not be a way to
// point mail scanning at something an account controls.
func ResolveClamdSocket(configured string) (string, bool) {
	if configured != "" && clamdSocketAnswers(configured) {
		return configured, false
	}
	for _, candidate := range clamdSocketCandidates {
		if candidate == configured {
			continue
		}
		if !clamdSocketTrusted(candidate) {
			continue
		}
		if clamdSocketAnswers(candidate) {
			return candidate, true
		}
	}
	return configured, false
}

// clamdSocketTrusted reports whether a socket and the directory holding it are
// out of reach of every account but root and this process.
func clamdSocketTrusted(path string) bool {
	if !clamdPathTrusted(path) {
		return false
	}
	// The directory decides who can replace the socket, so it matters as much
	// as the socket itself.
	return clamdPathTrusted(filepath.Dir(path))
}

func clamdPathTrusted(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if info.Mode().Perm()&0o002 != 0 && info.Mode()&os.ModeSticky == 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	uid := int(stat.Uid)
	return uid == 0 || uid == os.Geteuid()
}

// clamdSocketAnswers reports whether clamd itself is listening. Connecting
// proves only that something is there; PING proves it speaks the protocol CSM
// is about to hand mail to.
func clamdSocketAnswers(path string) bool {
	conn, err := net.DialTimeout("unix", path, clamdDialTimeout)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	if setErr := conn.SetDeadline(time.Now().Add(clamdDialTimeout)); setErr != nil {
		return false
	}
	if _, writeErr := conn.Write([]byte("zPING\x00")); writeErr != nil {
		return false
	}
	buf := make([]byte, 16)
	n, readErr := conn.Read(buf)
	if readErr != nil || n == 0 {
		return false
	}
	return strings.Contains(strings.ToUpper(string(buf[:n])), "PONG")
}
