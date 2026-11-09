package challenge

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestServeClosesListenerOnTLSFailure(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.TLSCert = filepath.Join(t.TempDir(), "absent.crt")
	cfg.Challenge.TLSKey = filepath.Join(t.TempDir(), "absent.key")
	s := New(cfg, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	// Serve loads TLS material again after Listen validated it. A rotation
	// can remove it in between; the bound listener must still be closed.
	if serveErr := s.Serve(ln); serveErr == nil {
		t.Fatal("Serve accepted missing TLS material")
	}
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatal("Serve left the listener accepting connections after TLS failure")
	}
}
