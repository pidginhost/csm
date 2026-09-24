package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A long-running handler extends its write deadline past the server's
// WriteTimeout. The hardening run set a deadline shorter than the default,
// so an audit that took a few minutes saved its report and then failed to
// answer.
func TestHardeningRunDoesNotShortenTheWriteDeadline(t *testing.T) {
	s := newTestServer(t, "tok")
	rec := newDeadlineRecorder()
	start := time.Now()
	s.apiHardeningRun(rec, httptest.NewRequest(http.MethodPost, "/api/v1/hardening/run", nil))
	_, deadlines, _ := rec.snapshot()
	if len(deadlines) == 0 {
		t.Fatal("hardening run set no write deadline")
	}
	for _, d := range deadlines {
		if d.deadline.Before(start.Add(serverWriteTimeout)) {
			t.Fatalf("deadline %s is sooner than the server WriteTimeout of %s", d.deadline.Sub(start).Round(time.Second), serverWriteTimeout)
		}
	}
}
