package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

type fakeProber struct {
	byPath map[string]dropperProbe
	calls  int
}

func (f *fakeProber) probe(c dropperCandidate) dropperProbe {
	f.calls++
	if p, ok := f.byPath[c.Path]; ok {
		return p
	}
	// Default: conclusively vanished.
	return dropperProbe{Conclusive: true}
}

type capturedAlert struct {
	sev          alert.Severity
	check, path  string
	msg, details string
}

func newTestEngine(ttl time.Duration) (*dropperEngine, *[]capturedAlert) {
	var got []capturedAlert
	e := newDropperEngine(dropperEngineConfig{
		ttl:     ttl,
		selfPID: 999,
	})
	e.emit = func(sev alert.Severity, check, msg, details, path string) {
		got = append(got, capturedAlert{sev: sev, check: check, msg: msg, details: details, path: path})
	}
	return e, &got
}

func admitPHP(e *dropperEngine, now time.Time, path string) {
	c := dropperCandidate{
		Path:     path,
		Docroot:  "/home/alice/public_html",
		Observed: now,
		Created:  true,
		Device:   41,
		Inode:    7001,
		Mode:     0o100644,
		Size:     1621,
		PID:      4242,
		Head:     []byte("<?php if (isset($_GET['k'])) { system($_POST['c']); }"),
	}
	e.tr.Observe(c)
}

func TestEngineProbeStepEmitsVanishedDropper(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	e, got := newTestEngine(3 * time.Minute)
	admitPHP(e, now, "/home/alice/public_html/wp-content/plugins/x/x.php")

	prober := &fakeProber{}
	// Before TTL: nothing due, nothing emitted.
	e.probeStep(now.Add(time.Minute), prober, now.Add(time.Minute))
	if prober.calls != 0 || len(*got) != 0 {
		t.Fatalf("early step probed=%d emitted=%d, want 0/0", prober.calls, len(*got))
	}

	// After TTL: probe says vanished -> held -> after grace -> emitted Critical.
	e.probeStep(now.Add(4*time.Minute), prober, now.Add(4*time.Minute))
	e.probeStep(now.Add(4*time.Minute+dropperGraceWindow+time.Second), prober, now.Add(4*time.Minute+dropperGraceWindow+time.Second))
	if len(*got) != 1 {
		t.Fatalf("emitted %d findings, want 1", len(*got))
	}
	a := (*got)[0]
	if a.sev != alert.Critical || a.check != "self_deleting_dropper_realtime" {
		t.Errorf("alert = %+v, want Critical self_deleting_dropper_realtime", a)
	}
}

func TestEngineProbeStepSuppressesSurvivor(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	e, got := newTestEngine(time.Minute)
	path := "/home/alice/public_html/wp-content/plugins/x/x.php"
	admitPHP(e, now, path)

	prober := &fakeProber{byPath: map[string]dropperProbe{
		path: {Conclusive: true, AtPath: &dropperFileState{Path: path, Device: 41, Inode: 7001, Size: 1621}},
	}}
	future := now.Add(2 * time.Minute)
	e.probeStep(future, prober, future)
	e.probeStep(future.Add(dropperGraceWindow+time.Second), prober, future.Add(dropperGraceWindow+time.Second))
	if len(*got) != 0 {
		t.Fatalf("surviving file emitted %d findings, want 0", len(*got))
	}
}

func TestEngineProbeStepRequeuesInconclusiveThenGivesUp(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	e, got := newTestEngine(time.Minute)
	path := "/home/alice/public_html/wp-content/plugins/x/x.php"
	admitPHP(e, now, path)

	prober := &fakeProber{byPath: map[string]dropperProbe{
		path: {Conclusive: false}, // transient failure every time
	}}
	// Each due step re-probes; after maxDropperProbeAttempts it is dropped.
	step := now.Add(2 * time.Minute)
	for i := 0; i < maxDropperProbeAttempts+2; i++ {
		e.probeStep(step, prober, step)
		step = step.Add(time.Second)
	}
	if len(*got) != 0 {
		t.Fatalf("inconclusive probe emitted %d findings, want 0", len(*got))
	}
	if prober.calls != maxDropperProbeAttempts {
		t.Errorf("prober called %d times, want capped at %d", prober.calls, maxDropperProbeAttempts)
	}
	if e.tr.trackedCount() != 0 {
		t.Errorf("candidate still tracked after giving up: %d", e.tr.trackedCount())
	}
}

func TestEngineAdmitGatesOnShouldTrack(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	e, _ := newTestEngine(time.Minute)

	// A stale (non-created, no birth) file must not be admitted.
	stale := dropperCandidate{
		Path: "/home/alice/public_html/x.php", Docroot: "/home/alice/public_html",
		Observed: now, Mode: 0o100644, Inode: 1, Device: 1,
	}
	if e.admit(stale) {
		t.Error("stale non-created candidate must not be admitted")
	}
	if e.tr.trackedCount() != 0 {
		t.Errorf("tracker holds %d after rejected admit, want 0", e.tr.trackedCount())
	}

	fresh := stale
	fresh.Created = true
	if !e.admit(fresh) {
		t.Error("fresh created candidate must be admitted")
	}
	if e.tr.trackedCount() != 1 {
		t.Errorf("tracker holds %d after admit, want 1", e.tr.trackedCount())
	}
}
