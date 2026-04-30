package checks

import (
	"testing"
)

func TestParseAFAlgEvent_BasicSyscallRecord(t *testing.T) {
	line := `type=SYSCALL msg=audit(1761826283.452:91234): arch=c000003e syscall=41 success=yes exit=3 a0=38 a1=5 a2=2 a3=0 items=0 ppid=12 pid=42 auid=1001 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=pts0 ses=2 comm="exploit" exe="/home/badguy/exploit" key="csm_af_alg_socket"`
	ev, ok := parseAFAlgEvent(line)
	if !ok {
		t.Fatal("expected a parsed event, got none")
	}
	if ev.UID != "1001" {
		t.Errorf("UID = %q, want 1001", ev.UID)
	}
	if ev.AUID != "1001" {
		t.Errorf("AUID = %q, want 1001", ev.AUID)
	}
	if ev.Exe != "/home/badguy/exploit" {
		t.Errorf("Exe = %q, want /home/badguy/exploit", ev.Exe)
	}
	if ev.Comm != "exploit" {
		t.Errorf("Comm = %q, want exploit", ev.Comm)
	}
	if ev.Timestamp != "1761826283.452" {
		t.Errorf("Timestamp = %q, want 1761826283.452", ev.Timestamp)
	}
	if ev.Serial != "91234" {
		t.Errorf("Serial = %q, want 91234", ev.Serial)
	}
}

func TestParseAFAlgEvent_RejectsLineWithoutKey(t *testing.T) {
	line := `type=SYSCALL msg=audit(1761826283.452:91234): syscall=41 a0=38 uid=1001 exe="/usr/bin/curl"`
	if _, ok := parseAFAlgEvent(line); ok {
		t.Error("line without csm_af_alg_socket key should be rejected")
	}
}

func TestParseAFAlgEvent_RejectsDifferentKey(t *testing.T) {
	line := `type=SYSCALL msg=audit(1.0:1): a0=38 uid=1001 exe="/x" key="csm_passwd_exec"`
	if _, ok := parseAFAlgEvent(line); ok {
		t.Error("line with different audit key should be rejected")
	}
}

func TestParseAFAlgEvent_HandlesQuotedExeWithSpaces(t *testing.T) {
	line := `type=SYSCALL msg=audit(1.0:1): a0=38 uid=1001 comm="my prog" exe="/path with space/x" key="csm_af_alg_socket"`
	ev, ok := parseAFAlgEvent(line)
	if !ok {
		t.Fatal("expected parsed event")
	}
	if ev.Exe != "/path with space/x" {
		t.Errorf("Exe = %q, want /path with space/x", ev.Exe)
	}
	if ev.Comm != "my prog" {
		t.Errorf("Comm = %q, want %q", ev.Comm, "my prog")
	}
}

func TestParseAFAlgEvent_RejectsMalformedTimestamp(t *testing.T) {
	line := `type=SYSCALL msg=audit(garbage): a0=38 uid=1001 exe="/x" key="csm_af_alg_socket"`
	if _, ok := parseAFAlgEvent(line); ok {
		t.Error("malformed audit() block should be rejected")
	}
}

func TestEventIsAfter_StrictOrdering(t *testing.T) {
	cases := []struct {
		a, b   afAlgEvent
		expect bool
	}{
		{afAlgEvent{Timestamp: "100.5", Serial: "1"}, afAlgEvent{Timestamp: "100.4", Serial: "999"}, true},
		{afAlgEvent{Timestamp: "100.5", Serial: "2"}, afAlgEvent{Timestamp: "100.5", Serial: "1"}, true},
		{afAlgEvent{Timestamp: "100.5", Serial: "1"}, afAlgEvent{Timestamp: "100.5", Serial: "1"}, false},
		{afAlgEvent{Timestamp: "100.4", Serial: "9"}, afAlgEvent{Timestamp: "100.5", Serial: "1"}, false},
	}
	for i, c := range cases {
		if got := c.a.after(c.b); got != c.expect {
			t.Errorf("case %d: %+v.after(%+v) = %v, want %v", i, c.a, c.b, got, c.expect)
		}
	}
}
