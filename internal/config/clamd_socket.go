package config

import (
	"net"
	"time"
)

// clamdSocketCandidates are the unix sockets a clamd is normally reachable on.
// The path is set by whoever packaged clamd, not by CSM: RHEL's clamd-scan,
// Debian's clamav-daemon and cPanel's bundled clamd all choose differently, and
// a host whose setting names the wrong one scans no mail at all while every
// health signal still reports the watcher as running.
var clamdSocketCandidates = []string{
	"/var/run/clamd.scan/clamd.sock",
	"/run/clamd.scan/clamd.sock",
	"/var/run/clamav/clamd.ctl",
	"/run/clamav/clamd.ctl",
	"/var/run/clamav/clamd.sock",
	"/run/clamav/clamd.sock",
	"/usr/local/cpanel/3rdparty/var/clamav/clamd.sock",
	"/var/clamd",
	"/tmp/clamd.socket",
}

// clamdDialTimeout bounds each probe. The candidate list is walked on a health
// path, so a hung socket must not hold the caller.
const clamdDialTimeout = 300 * time.Millisecond

// ResolveClamdSocket returns the socket to talk to clamd on, and whether it had
// to be discovered because the configured one was not answering.
//
// The configured path always wins when something is listening on it. Only when
// it is not does CSM fall back to a well-known location, because refusing to
// scan mail is the worse failure: silence there looks exactly like clean mail.
func ResolveClamdSocket(configured string) (string, bool) {
	if configured != "" && clamdSocketAnswers(configured) {
		return configured, false
	}
	for _, candidate := range clamdSocketCandidates {
		if candidate == configured {
			continue
		}
		if clamdSocketAnswers(candidate) {
			return candidate, true
		}
	}
	return configured, false
}

func clamdSocketAnswers(path string) bool {
	conn, err := net.DialTimeout("unix", path, clamdDialTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
