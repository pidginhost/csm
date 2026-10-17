package ipmap

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCanaryReportsStaleMapAfterGrace(t *testing.T) {
	st := State{Gen: "abcdef012345", WrittenAt: now}
	if p := CanaryProblem(st, "abcdef012345", nil, now.Add(time.Hour)); p != "" {
		t.Fatalf("current map flagged: %q", p)
	}
	if p := CanaryProblem(st, "", nil, now.Add(4*time.Minute)); p != "" {
		t.Fatalf("flagged inside the grace: %q", p)
	}
	if p := CanaryProblem(st, "", nil, now.Add(6*time.Minute)); !strings.Contains(p, "not using the current CSM IP map") {
		t.Fatalf("stale map not flagged: %q", p)
	}
	if p := CanaryProblem(st, "111111111111", nil, now.Add(6*time.Minute)); !strings.Contains(p, "111111111111") {
		t.Fatalf("old generation not named: %q", p)
	}
	if p := CanaryProblem(st, "", errors.New("dial unix: no such file"), now.Add(6*time.Minute)); !strings.Contains(p, "could not ask rspamd") {
		t.Fatalf("probe failure not named: %q", p)
	}
}

func TestCanaryReportsWriteFailure(t *testing.T) {
	st := State{Gen: "abcdef012345", WrittenAt: now, Err: errors.New("writing /var/lib/csm-rspamd/csm_ip.map: no space left on device")}
	if p := CanaryProblem(st, "abcdef012345", nil, now); !strings.Contains(p, "could not write the IP map") || !strings.Contains(p, "keeps using the previous map") {
		t.Fatalf("write failure = %q", p)
	}
	if p := CanaryProblem(State{}, "", nil, now); p != "" {
		t.Fatalf("nothing written yet = %q", p)
	}
}
