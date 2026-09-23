package webui

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"
)

func serverWithOccupiedListener(t *testing.T) *Server {
	t.Helper()
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	s := newTestServer(t, randomBrowserCredential())
	s.cfg.WebUI.Listen = listener.Addr().String()
	s.httpSrv.Addr = listener.Addr().String()
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	return s
}

func TestTLSStartFailureStopsBackgroundWorkers(t *testing.T) {
	s := serverWithOccupiedListener(t)
	if err := s.Start(); err == nil {
		t.Fatal("occupied listener started")
	}
	select {
	case <-s.pruneDone:
	default:
		t.Fatal("listener failure left background workers running")
	}
}

func TestTLSStartDoesNotCreateMissingOperatorFiles(t *testing.T) {
	s := serverWithOccupiedListener(t)
	dir := t.TempDir()
	s.cfg.WebUI.TLSCert = filepath.Join(dir, "operator.crt")
	s.cfg.WebUI.TLSKey = filepath.Join(dir, "operator.key")
	if err := s.Start(); err == nil {
		t.Fatal("missing operator certificate accepted")
	}
	for _, path := range []string{s.cfg.WebUI.TLSCert, s.cfg.WebUI.TLSKey} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Error("startup created an operator-managed TLS file")
		}
	}
}

func TestCertificateRenewalLoopStopsOnShutdown(t *testing.T) {
	s := newTestServer(t, randomBrowserCredential())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.renewCertLoop(filepath.Join(t.TempDir(), "webui.crt"), filepath.Join(t.TempDir(), "webui.key"))
	}()
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("certificate worker did not stop")
	}
}

func TestDailyTLSRenewalDoesNotRecreateMissingFiles(t *testing.T) {
	for _, missing := range []string{"certificate", "key"} {
		t.Run(missing, func(t *testing.T) {
			s := newTestServer(t, randomBrowserCredential())
			dir := t.TempDir()
			certPath, keyPath := filepath.Join(dir, "webui.crt"), filepath.Join(dir, "webui.key")
			if err := EnsureTLSCert(certPath, keyPath); err != nil {
				t.Fatal(err)
			}
			missingPath, keptPath := certPath, keyPath
			if missing == "key" {
				missingPath, keptPath = keyPath, certPath
			}
			before, err := os.ReadFile(keptPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(missingPath); err != nil {
				t.Fatal(err)
			}
			synctest.Test(t, func(t *testing.T) {
				s.pruneDone = make(chan struct{})
				defer func() { _ = s.Shutdown(context.Background()) }()
				go s.renewCertLoop(certPath, keyPath)
				synctest.Wait()
				time.Sleep(24 * time.Hour)
				synctest.Wait()
				if _, err := os.Stat(missingPath); !os.IsNotExist(err) {
					t.Error("daily renewal recreated an absent TLS file")
				}
				after, err := os.ReadFile(keptPath)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before, after) {
					t.Error("daily renewal replaced the remaining TLS file")
				}
			})
		})
	}
}
