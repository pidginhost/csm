package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRspamdSource_ParsesScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/history" {
			t.Fatalf("expected /history request, got %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"rows":[{"ip":"1.2.3.4","action":"reject","score":8.5},{"ip":"5.6.7.8","action":"reject","score":99}]}`))
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

func TestRspamdSource_IgnoresOtherIPs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"rows":[{"ip":"5.6.7.8","action":"reject","score":99}]}`))
	}))
	defer srv.Close()

	src := NewRspamdSource(srv.URL, "", "")
	score, err := src.Score(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if score != 0 {
		t.Fatalf("expected no signal for unrelated history rows, got %d", score)
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
		_, _ = w.Write([]byte(`{"rows":[{"ip":"1.2.3.4","action":"reject","score":1}]}`))
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
