package webui

import (
	"path/filepath"
	"testing"

	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

func TestNewDisablesHTTP2ForWebSocketServer(t *testing.T) {
	cfg := &config.Config{
		Hostname:  "test-host",
		StatePath: t.TempDir(),
	}
	cfg.WebUI.Listen = "127.0.0.1:9443"
	cfg.WebUI.AuthToken = "test-token"
	cfg.WebUI.UIDir = filepath.Join(t.TempDir(), "missing-ui")

	store, err := state.Open(cfg.StatePath)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}

	srv, err := New(cfg, store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if srv.httpSrv.TLSNextProto == nil {
		t.Fatal("TLSNextProto is nil, HTTP/2 will be auto-enabled")
	}
	if _, ok := srv.httpSrv.TLSNextProto["h2"]; ok {
		t.Fatal("TLSNextProto unexpectedly contains h2")
	}

	if srv.httpSrv.TLSConfig == nil {
		t.Fatal("TLSConfig is nil")
	}

	if len(srv.httpSrv.TLSConfig.NextProtos) != 1 || srv.httpSrv.TLSConfig.NextProtos[0] != "http/1.1" {
		t.Fatalf("unexpected NextProtos: %#v", srv.httpSrv.TLSConfig.NextProtos)
	}
}
