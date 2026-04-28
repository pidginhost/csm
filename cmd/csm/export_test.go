package main

import (
	"testing"
	"time"
)

func TestParseSinceRFC3339(t *testing.T) {
	got, err := parseSince("2026-04-27T12:30:00Z")
	if err != nil {
		t.Fatalf("parseSince: %v", err)
	}
	want := time.Date(2026, 4, 27, 12, 30, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseSinceDuration(t *testing.T) {
	before := time.Now().UTC()
	got, err := parseSince("2h")
	if err != nil {
		t.Fatalf("parseSince: %v", err)
	}
	after := time.Now().UTC()
	wantLowerBound := before.Add(-2 * time.Hour).Add(-time.Second)
	wantUpperBound := after.Add(-2 * time.Hour).Add(time.Second)
	if got.Before(wantLowerBound) || got.After(wantUpperBound) {
		t.Errorf("2h yielded %v, expected near %v", got, before.Add(-2*time.Hour))
	}
}

func TestParseSinceDays(t *testing.T) {
	before := time.Now().UTC()
	got, err := parseSince("7d")
	if err != nil {
		t.Fatalf("parseSince: %v", err)
	}
	want := before.Add(-7 * 24 * time.Hour)
	delta := got.Sub(want)
	if delta < -time.Second || delta > time.Second {
		t.Errorf("7d yielded %v, expected near %v (delta %v)", got, want, delta)
	}
}

func TestParseSinceInvalid(t *testing.T) {
	cases := []string{"", "yesterday", "1week", "2026/04/27"}
	for _, c := range cases {
		if _, err := parseSince(c); err == nil {
			t.Errorf("parseSince(%q): expected error", c)
		}
	}
}
