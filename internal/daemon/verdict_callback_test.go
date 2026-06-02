package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/verdict"
)

func TestAskVerdictCallbackUsesActiveConfig(t *testing.T) {
	// Both endpoints echo the request nonce and a fresh timestamp so replay
	// checks pass; a secret is configured so the "allow" verdict is honored
	// (an unsigned allow with no secret is refused).
	echo := func(resp verdict.Response, hits *int32) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(hits, 1)
			var req verdict.Request
			_ = json.NewDecoder(r.Body).Decode(&req)
			resp.Nonce = req.Nonce
			resp.Timestamp = time.Now().Unix()
			_ = json.NewEncoder(w).Encode(resp)
		}
	}
	var oldHits, newHits int32
	oldSrv := httptest.NewServer(echo(verdict.Response{Verdict: "block", TenantID: "old-tenant", Note: "old-note"}, &oldHits))
	defer oldSrv.Close()
	newSrv := httptest.NewServer(echo(verdict.Response{Verdict: "allow", TenantID: "new-tenant", Note: "new-note"}, &newHits))
	defer newSrv.Close()

	optOut := false
	cfg := &config.Config{}
	cfg.AutoResponse.VerdictCallback.Enabled = true
	cfg.AutoResponse.VerdictCallback.URL = oldSrv.URL
	cfg.AutoResponse.VerdictCallback.TimeoutSec = 1
	cfg.AutoResponse.VerdictCallback.HMACSecret = "panel-secret"
	cfg.AutoResponse.VerdictCallback.RequireResponseSignature = &optOut
	d := &Daemon{cfg: &config.Config{}}
	config.SetActive(cfg)
	t.Cleanup(func() { config.SetActive(nil) })

	verdictValue, tenant, note, err := d.askVerdictCallback(context.Background(), "192.0.2.10", "test")
	if err != nil {
		t.Fatal(err)
	}
	if verdictValue != "block" || tenant != "old-tenant" || note != "old-note" {
		t.Fatalf("unexpected old verdict response: verdict=%q tenant=%q note=%q", verdictValue, tenant, note)
	}

	reloaded := *cfg
	reloaded.AutoResponse.VerdictCallback.URL = newSrv.URL
	config.SetActive(&reloaded)

	verdictValue, tenant, note, err = d.askVerdictCallback(context.Background(), "192.0.2.10", "test")
	if err != nil {
		t.Fatal(err)
	}
	if verdictValue != "allow" || tenant != "new-tenant" || note != "new-note" {
		t.Fatalf("unexpected reloaded verdict response: verdict=%q tenant=%q note=%q", verdictValue, tenant, note)
	}
	if atomic.LoadInt32(&oldHits) != 1 || atomic.LoadInt32(&newHits) != 1 {
		t.Fatalf("expected one hit to each active endpoint, old=%d new=%d", oldHits, newHits)
	}
}

func TestAskVerdictCallbackDisabledActiveConfigSkipsHTTP(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(verdict.Response{Verdict: "allow"})
	}))
	defer srv.Close()

	startup := &config.Config{}
	startup.AutoResponse.VerdictCallback.Enabled = true
	startup.AutoResponse.VerdictCallback.URL = srv.URL
	startup.AutoResponse.VerdictCallback.TimeoutSec = 1
	config.SetActive(&config.Config{})
	t.Cleanup(func() { config.SetActive(nil) })

	d := &Daemon{cfg: startup}
	verdictValue, tenant, note, err := d.askVerdictCallback(context.Background(), "192.0.2.10", "test")
	if err != nil {
		t.Fatal(err)
	}
	if verdictValue != "" || tenant != "" || note != "" {
		t.Fatalf("expected empty skip response, got verdict=%q tenant=%q note=%q", verdictValue, tenant, note)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("disabled active config still called endpoint %d time(s)", hits)
	}
}
