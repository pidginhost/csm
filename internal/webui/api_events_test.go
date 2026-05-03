package webui

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/broadcast"
	"github.com/pidginhost/csm/internal/config"
)

func TestApiEvents_StreamsFindings(t *testing.T) {
	bus := broadcast.NewBus(8)
	defer bus.Close()

	s := &Server{cfg: &config.Config{}}
	s.cfg.WebUI.Tokens = []config.WebUIToken{{Name: "t", Token: "secret", Scope: "read"}}
	s.SetFindingBus(bus)

	srv := httptest.NewServer(s.requireRead(http.HandlerFunc(s.apiEvents)))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("expected SSE content type, got %q", resp.Header.Get("Content-Type"))
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		bus.Publish(alert.Finding{Check: "x", Severity: alert.High})
	}()

	scanner := bufio.NewScanner(resp.Body)
	deadline := time.Now().Add(time.Second)
	gotData := false
	for scanner.Scan() && time.Now().Before(deadline) {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, `"check":"x"`) {
			gotData = true
			break
		}
	}
	if !gotData {
		t.Fatal("expected data line containing finding JSON")
	}
}

func TestApiEvents_NilBusReturns503(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	s.cfg.WebUI.Tokens = []config.WebUIToken{{Name: "t", Token: "secret", Scope: "read"}}
	// Do NOT call SetFindingBus — leave nil

	srv := httptest.NewServer(s.requireRead(http.HandlerFunc(s.apiEvents)))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}
