// Package sdnotify is a thin wrapper around go-systemd's daemon notification
// helpers. The daemon calls Ready when watchers are attached, Status to
// publish a one-line state visible in `systemctl status`, and Watchdog on a
// recurring ticker so systemd's WatchdogSec= keep-alive doesn't expire.
//
// Every function is a no-op when NOTIFY_SOCKET is unset (the daemon is not
// running under systemd; e.g. dev mode). That contract makes it safe to call
// these helpers unconditionally without runtime gates in the daemon code.
package sdnotify

import (
	systemd "github.com/coreos/go-systemd/v22/daemon"
)

// Ready signals systemd that the daemon has finished startup. Returns
// (true, nil) when the notification was delivered, (false, nil) when
// NOTIFY_SOCKET is unset, or (false, err) on a real I/O error.
func Ready() (bool, error) {
	return systemd.SdNotify(false, systemd.SdNotifyReady)
}

// Reloading signals systemd that the daemon is reloading its config.
func Reloading() (bool, error) {
	return systemd.SdNotify(false, systemd.SdNotifyReloading)
}

// Status sets a single-line status string visible in `systemctl status csm`.
func Status(msg string) (bool, error) {
	return systemd.SdNotify(false, "STATUS="+msg)
}

// Watchdog pings the systemd watchdog. Required when the unit declares
// WatchdogSec=; without periodic pings systemd will restart the daemon
// after WatchdogSec elapses.
func Watchdog() (bool, error) {
	return systemd.SdNotify(false, systemd.SdNotifyWatchdog)
}
