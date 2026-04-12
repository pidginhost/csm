package webui

import (
	"testing"
	"time"
)

func TestFormatBlockedViewPermanent(t *testing.T) {
	b := blockedEntry{
		IP:        "203.0.113.5",
		Reason:    "brute-force",
		BlockedAt: time.Now(),
	}
	view, ok := formatBlockedView(b)
	if !ok {
		t.Fatal("non-expired entry should return ok=true")
	}
	if view.IP != "203.0.113.5" {
		t.Errorf("IP = %q", view.IP)
	}
	if view.ExpiresIn != "permanent" {
		t.Errorf("ExpiresIn = %q, want permanent", view.ExpiresIn)
	}
}

func TestFormatBlockedViewTemporary(t *testing.T) {
	b := blockedEntry{
		IP:        "198.51.100.1",
		Reason:    "waf-block",
		BlockedAt: time.Now(),
		ExpiresAt: time.Now().Add(2 * time.Hour),
	}
	view, ok := formatBlockedView(b)
	if !ok {
		t.Fatal("future expiry should return ok=true")
	}
	if view.ExpiresIn == "permanent" {
		t.Error("temporary block should not be permanent")
	}
	if view.ExpiresAt == "" {
		t.Error("ExpiresAt should be set for temporary blocks")
	}
}

func TestFormatBlockedViewExpired(t *testing.T) {
	b := blockedEntry{
		IP:        "10.0.0.1",
		Reason:    "old",
		BlockedAt: time.Now().Add(-3 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	_, ok := formatBlockedView(b)
	if ok {
		t.Error("expired entry should return ok=false")
	}
}

func TestFormatBlockedViewInfersSource(t *testing.T) {
	b := blockedEntry{
		IP:        "203.0.113.5",
		Reason:    "auto-block: brute-force",
		BlockedAt: time.Now(),
	}
	view, _ := formatBlockedView(b)
	if view.Source == "" {
		t.Error("Source should be inferred when empty")
	}
}
