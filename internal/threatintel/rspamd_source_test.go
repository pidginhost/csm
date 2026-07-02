package threatintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

// rspamdRow builds one history row. unixTime <= 0 omits the timestamp,
// matching rspamd deployments whose history rows carry no unix_time.
func rspamdRow(ip, action string, score float64, unixTime float64) map[string]any {
	row := map[string]any{"ip": ip, "action": action, "score": score}
	if unixTime > 0 {
		row["unix_time"] = unixTime
	}
	return row
}

func repeatRspamdRows(n int, ip, action string, score float64, unixTime float64) []map[string]any {
	rows := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, rspamdRow(ip, action, score, unixTime))
	}
	return rows
}

// TestRspamdSource_ScoresOnlySpamVerdicts pins the scoring contract:
// only definitive spam verdicts (reject, add header, rewrite subject)
// contribute, weighted by recency and diluted by delivered ham, so a
// benign correspondent MTA can never accumulate its way over the
// auto-block threshold (50) just by sending mail regularly.
func TestRspamdSource_ScoresOnlySpamVerdicts(t *testing.T) {
	const (
		mtaIP   = "192.0.2.10"
		decoyIP = "198.51.100.9"
		// Mirrors abuseConfidenceThreshold in internal/checks: at or
		// above this the reputation check emits a Critical finding.
		blockThreshold = 50
	)
	now := float64(time.Now().Unix())
	yearAgo := now - 365*24*3600

	cases := []struct {
		name string
		rows []map[string]any
		want int
	}{
		{
			name: "empty history",
			rows: nil,
			want: 0,
		},
		{
			name: "pure ham high volume MTA",
			rows: repeatRspamdRows(200, mtaIP, "no action", 3.2, 0),
			want: 0,
		},
		{
			name: "hammy negative scores stay at zero",
			rows: repeatRspamdRows(5, mtaIP, "no action", -8.0, 0),
			want: 0,
		},
		{
			name: "greylist first-contact burst never scores",
			rows: repeatRspamdRows(12, mtaIP, "greylist", 5.0, 0),
			want: 0,
		},
		{
			name: "soft reject tempfails never score",
			rows: repeatRspamdRows(12, mtaIP, "soft reject", 6.0, 0),
			want: 0,
		},
		{
			name: "single reject stays below block threshold",
			rows: repeatRspamdRows(1, mtaIP, "reject", 15.2, 0),
			want: 33,
		},
		{
			name: "two rejects with no ham sit exactly at block threshold",
			rows: repeatRspamdRows(2, mtaIP, "reject", 22.0, 0),
			want: blockThreshold,
		},
		{
			name: "single reject among many delivered ham near zero",
			rows: append(
				repeatRspamdRows(150, mtaIP, "no action", 1.1, 0),
				rspamdRow(mtaIP, "reject", 18.0, 0),
			),
			want: 1,
		},
		{
			name: "mixed mostly ham stays below block threshold",
			rows: append(
				repeatRspamdRows(20, mtaIP, "no action", 0.5, 0),
				repeatRspamdRows(3, mtaIP, "reject", 20.0, 0)...,
			),
			want: 12,
		},
		{
			name: "persistent rejects score high",
			rows: repeatRspamdRows(20, mtaIP, "reject", 25.0, 0),
			want: 91,
		},
		{
			name: "spam-folder verdicts weigh below reject",
			rows: repeatRspamdRows(2, mtaIP, "add header", 8.0, 0),
			want: 35,
		},
		{
			name: "rewrite subject same tier as add header",
			rows: repeatRspamdRows(2, mtaIP, "rewrite subject", 8.0, 0),
			want: 35,
		},
		{
			name: "year-old rejects decay to zero",
			rows: repeatRspamdRows(3, mtaIP, "reject", 25.0, yearAgo),
			want: 0,
		},
		{
			name: "year-old spam ignored next to fresh ham",
			rows: append(
				repeatRspamdRows(5, mtaIP, "no action", 1.0, 0),
				rspamdRow(mtaIP, "add header", 9.0, yearAgo),
			),
			want: 0,
		},
		{
			name: "fresh rejects score despite stale good history",
			rows: append(
				repeatRspamdRows(400, mtaIP, "no action", 1.0, yearAgo),
				repeatRspamdRows(10, mtaIP, "reject", 25.0, 0)...,
			),
			want: 83,
		},
		{
			name: "other IP rejects do not bleed over",
			rows: repeatRspamdRows(10, decoyIP, "reject", 30.0, 0),
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"rows": tc.rows})
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(body)
			}))
			defer srv.Close()

			src := NewRspamdSource(srv.URL, "", "")
			got, err := src.Score(context.Background(), mtaIP)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("score = %d, want %d", got, tc.want)
			}
		})
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
