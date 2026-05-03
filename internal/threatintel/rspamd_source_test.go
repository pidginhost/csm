package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRspamdSource_ParsesScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"actions":{"reject":12},"learns":0}`))
	}))
	defer srv.Close()

	src := NewRspamdSource(srv.URL, "", "")
	score, err := src.Score(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if score == 0 {
		t.Fatal("expected non-zero score for IP with rejects")
	}
}

func TestRspamdSource_UnreachableReturnsError(t *testing.T) {
	src := NewRspamdSource("http://127.0.0.1:1", "", "") // refused
	_, err := src.Score(context.Background(), "1.2.3.4")
	if err == nil {
		t.Fatal("expected error on connection refused")
	}
}

func TestRspamdSource_ResolvesTokenFromEnv(t *testing.T) {
	const envVar = "TEST_RSPAMD_TOKEN"
	t.Setenv(envVar, "secret-from-env")

	var capturedPassword string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPassword = r.Header.Get("Password")
		_, _ = w.Write([]byte(`{"actions":{"reject":1}}`))
	}))
	defer srv.Close()

	// Static token left empty; env var should win at Score time.
	src := NewRspamdSource(srv.URL, "", envVar)
	if _, err := src.Score(context.Background(), "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if capturedPassword != "secret-from-env" {
		t.Fatalf("expected env-resolved token, got %q", capturedPassword)
	}
}
