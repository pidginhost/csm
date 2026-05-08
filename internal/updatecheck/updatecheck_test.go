package updatecheck

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"2.13.0", "2.12.0", true},
		{"2.12.0", "2.12.0", false},
		{"2.12.0", "2.13.0", false},
		{"2.12.1", "2.12.0", true},
		{"v2.13.0", "v2.12.5", true},
		{"2.13.0", "dev", true},
		{"2.13.0", "", true},
		{"", "2.13.0", false},
		{"2.13.0-rc.1", "2.13.0", false},
	}
	for _, c := range cases {
		got := isNewer(c.a, c.b)
		if got != c.want {
			t.Errorf("isNewer(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestParseAptPolicy(t *testing.T) {
	out := `csm:
  Installed: 2.12.0
  Candidate: 2.13.1
  Version table:
 *** 2.12.0 100
        100 /var/lib/dpkg/status
     2.13.1 500
        500 https://repo.example.com stable/main amd64 Packages
`
	v, err := parseAptPolicy(out)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v != "2.13.1" {
		t.Fatalf("got %q want 2.13.1", v)
	}
}

func TestParseAptPolicy_None(t *testing.T) {
	out := "csm:\n  Installed: (none)\n  Candidate: (none)\n"
	if _, err := parseAptPolicy(out); err == nil {
		t.Fatal("expected error on (none)")
	}
}

func TestParseAptPolicy_StripsEpochAndRevision(t *testing.T) {
	out := "csm:\n  Candidate: 2:2.13.1-1\n"
	v, err := parseAptPolicy(out)
	if err != nil {
		t.Fatal(err)
	}
	if v != "2.13.1" {
		t.Fatalf("got %q want 2.13.1", v)
	}
}

func TestParseDnfRepoquery_PicksHighest(t *testing.T) {
	out := "2.12.0\n2.13.0\n2.11.5\n"
	v, err := parseDnfRepoquery(out)
	if err != nil {
		t.Fatal(err)
	}
	if v != "2.13.0" {
		t.Fatalf("got %q want 2.13.0", v)
	}
}

func TestParseDnfRepoquery_Empty(t *testing.T) {
	if _, err := parseDnfRepoquery(""); err == nil {
		t.Fatal("expected error on empty output")
	}
}

func TestCheckOnce_GitHubAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"tag_name":"v2.13.0"}`)
	}))
	defer srv.Close()

	c := New(Options{
		CurrentVersion: "2.12.0",
		GitHubAPIURL:   srv.URL,
	})
	got := c.CheckOnce(context.Background())
	if got.Err != "" {
		t.Fatalf("unexpected err: %s", got.Err)
	}
	if got.LatestVersion != "2.13.0" {
		t.Fatalf("latest=%q want 2.13.0", got.LatestVersion)
	}
	if !got.Available {
		t.Fatal("expected available=true")
	}
	if got.Source != "github" {
		t.Fatalf("source=%q want github", got.Source)
	}
}

func TestCheckOnce_NoUpdateWhenSame(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, `{"tag_name":"v2.13.0"}`)
	}))
	defer srv.Close()

	c := New(Options{CurrentVersion: "2.13.0", GitHubAPIURL: srv.URL})
	got := c.CheckOnce(context.Background())
	if got.Available {
		t.Fatal("expected available=false when versions match")
	}
}

func TestCheckOnce_FallsBackToPackageOnGitHubError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := New(Options{
		CurrentVersion: "2.12.0",
		GitHubAPIURL:   srv.URL,
		PackageProbe:   AptProbe("csm"), // tag aside, parsed by reflection in pkgSourceLabel
	})
	// Override the probe with an inline closure since AptProbe touches exec.
	c.opts.PackageProbe = func(ctx context.Context) (string, error) {
		return "2.13.0", nil
	}

	got := c.CheckOnce(context.Background())
	if got.Err != "" {
		t.Fatalf("unexpected err: %s", got.Err)
	}
	if got.LatestVersion != "2.13.0" {
		t.Fatalf("latest=%q want 2.13.0", got.LatestVersion)
	}
	if !got.Available {
		t.Fatal("expected available=true after fallback")
	}
}

func TestCheckOnce_PreservesPreviousOnDoubleFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, `{"tag_name":"v2.13.0"}`)
	}))

	c := New(Options{CurrentVersion: "2.12.0", GitHubAPIURL: srv.URL})
	first := c.CheckOnce(context.Background())
	if first.LatestVersion != "2.13.0" || first.Err != "" {
		t.Fatalf("first poll bad: %+v", first)
	}

	srv.Close() // dial errors after this

	c.opts.PackageProbe = func(ctx context.Context) (string, error) {
		return "", errors.New("apt missing")
	}

	second := c.CheckOnce(context.Background())
	if second.Err == "" {
		t.Fatal("expected err on double failure")
	}
	if second.LatestVersion != "2.13.0" || !second.Available {
		t.Fatalf("expected previous result preserved: %+v", second)
	}
}

func TestCheckOnce_GitHubEmptyTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, `{"tag_name":""}`)
	}))
	defer srv.Close()

	c := New(Options{CurrentVersion: "2.12.0", GitHubAPIURL: srv.URL})
	got := c.CheckOnce(context.Background())
	if got.Err == "" {
		t.Fatal("expected err on empty tag_name")
	}
}

func TestNew_DefaultsApplied(t *testing.T) {
	c := New(Options{CurrentVersion: "2.12.0"})
	if c.opts.Interval < time.Hour {
		t.Fatalf("interval=%v want clamped to >=1h", c.opts.Interval)
	}
	if c.opts.GitHubAPIURL == "" {
		t.Fatal("default GitHub URL not set")
	}
	if c.opts.HTTPClient == nil {
		t.Fatal("default HTTP client not set")
	}
}

func TestPkgSourceLabel(t *testing.T) {
	if got := pkgSourceLabel(AptProbe("csm")); got != "apt" {
		t.Errorf("apt label=%q", got)
	}
	if got := pkgSourceLabel(DnfProbe("csm")); got != "dnf" {
		t.Errorf("dnf label=%q", got)
	}
	if got := pkgSourceLabel(nil); got != "package" {
		t.Errorf("nil label=%q", got)
	}
}
