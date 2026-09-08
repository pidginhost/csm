package main

import "testing"

func TestSystemdShutdownLetsDaemonStopWorkers(t *testing.T) {
	// Sending SIGTERM to the whole cgroup lets the worker exit before the
	// daemon handles its own signal and closes stopCh. Signal the daemon
	// first; systemd must still kill the entire cgroup after the stop timeout.
	fields := unitDirectiveFields(systemdServiceUnit("/opt/csm/csm"), "KillMode")
	if len(fields) != 1 || !fields["mixed"] {
		t.Fatalf("KillMode = %v, want mixed for ordered worker shutdown", fields)
	}
}
