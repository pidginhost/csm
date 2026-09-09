package main

import (
	"strings"
	"testing"
)

// systemd 239 (EL8, CloudLinux 8) does not know ProtectHostname (242),
// ProtectKernelLogs (244) or ProtectClock (245). It logs "Unknown lvalue" for
// each at every start and ignores them, so the generated unit must not carry
// them there; every other directive stays.
func TestSystemdServiceUnitForOldSystemdOmitsUnknownDirectives(t *testing.T) {
	full := systemdServiceUnit("/opt/csm/csm")
	old := systemdServiceUnitFor("/opt/csm/csm", 239)
	for _, gone := range []string{"ProtectKernelLogs=", "ProtectClock=", "ProtectHostname="} {
		if strings.Contains(old, gone) {
			t.Errorf("systemd 239 unit still carries %q, which that systemd rejects", gone)
		}
	}
	// The comment that explains the dropped directive goes with it.
	if strings.Contains(old, "read dmesg") {
		t.Error("systemd 239 unit keeps the comment for a directive it no longer has")
	}
	for _, keep := range []string{
		"ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectSystem=strict",
		"SystemCallFilter=~", "ReadWritePaths=-/var/cache/kcare", "PrivateDevices=no",
	} {
		if !strings.Contains(old, keep) {
			t.Errorf("systemd 239 unit lost %q", keep)
		}
	}
	if strings.Contains(old, "\n\n\n") {
		t.Error("dropping directives left a double blank line")
	}

	// 244 knows ProtectHostname and ProtectKernelLogs but not ProtectClock.
	v244 := systemdServiceUnitFor("/opt/csm/csm", 244)
	if !strings.Contains(v244, "ProtectKernelLogs=no") || !strings.Contains(v244, "ProtectHostname=yes") {
		t.Error("systemd 244 unit lost a directive it supports")
	}
	if strings.Contains(v244, "ProtectClock=") {
		t.Error("systemd 244 unit carries ProtectClock, added in 245")
	}

	for _, v := range []int{245, 252, 0} {
		if got := systemdServiceUnitFor("/opt/csm/csm", v); got != full {
			t.Errorf("systemd version %d must receive the full unit", v)
		}
	}
}

func TestParseSystemdVersion(t *testing.T) {
	cases := map[string]int{
		"systemd 239 (239-82.el8_10.19)\n+PAM +AUDIT +SELINUX\n": 239,
		"systemd 252 (252.23-1~deb12u1)":                         252,
		"systemd 255\n":                                          255,
		"":                                                       0,
		"garbage output":                                         0,
		"systemd abc":                                            0,
	}
	for in, want := range cases {
		if got := parseSystemdVersion(in); got != want {
			t.Errorf("parseSystemdVersion(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestUnsupportedSystemdDirectivesNamesWhatIsDropped(t *testing.T) {
	if got := unsupportedSystemdDirectives(239); strings.Join(got, ",") != "ProtectHostname,ProtectKernelLogs,ProtectClock" {
		t.Errorf("239: %v", got)
	}
	if got := unsupportedSystemdDirectives(244); strings.Join(got, ",") != "ProtectClock" {
		t.Errorf("244: %v", got)
	}
	for _, v := range []int{245, 0} {
		if got := unsupportedSystemdDirectives(v); len(got) != 0 {
			t.Errorf("%d: %v, want none", v, got)
		}
	}
}
